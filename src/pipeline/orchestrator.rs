use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use crate::container::ContainerManager;
use crate::errors::SekuraError;
use crate::llm;
use crate::llm::provider::LLMProvider;
use crate::models::finding::{Finding, VulnCategory};
use crate::repl::events::PipelineEvent;
use crate::reporting::formatter::{format_executive_summary, format_finding_markdown};
use crate::techniques::TechniqueLibrary;
use super::state::*;
use super::phase::PHASES;
use tracing::{info, warn, error};

pub struct PipelineOrchestrator {
    config: PipelineConfig,
    state: Arc<RwLock<PipelineState>>,
    cancel_token: CancellationToken,
    container: Arc<ContainerManager>,
    llm: Arc<dyn LLMProvider>,
    technique_library: Arc<TechniqueLibrary>,
    event_tx: Option<mpsc::UnboundedSender<PipelineEvent>>,
    findings: Arc<RwLock<Vec<Finding>>>,
}

impl PipelineOrchestrator {
    pub async fn new(config: PipelineConfig) -> Result<Self, SekuraError> {
        // Create output directories
        tokio::fs::create_dir_all(config.deliverables_dir()).await?;
        tokio::fs::create_dir_all(config.audit_dir()).await?;

        // Initialize container manager
        let container = Arc::new(
            ContainerManager::new(&config.container_config).await?
        );

        // Initialize LLM provider
        let llm: Arc<dyn LLMProvider> = Arc::from(
            llm::create_provider(
                &config.provider,
                &config.api_key,
                config.model.as_deref(),
                Some(&config.base_url),
            )?
        );

        // Load technique definitions
        let techniques_dir = std::env::current_dir()?.join("techniques");
        let technique_library = Arc::new(TechniqueLibrary::load(&techniques_dir)?);

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(PipelineState::new())),
            cancel_token: CancellationToken::new(),
            container,
            llm,
            technique_library,
            event_tx: None,
            findings: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Attach an event channel for streaming pipeline events to a REPL or other consumer.
    pub fn with_event_channel(mut self, tx: mpsc::UnboundedSender<PipelineEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// Emit a pipeline event if an event channel is attached.
    fn emit(&self, event: PipelineEvent) {
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(event);
        }
    }

    fn emit_phase_started(&self, phase: &PhaseName) {
        let display_name = PHASES
            .iter()
            .find(|p| p.name == *phase)
            .map(|p| p.display_name)
            .unwrap_or("Unknown");
        self.emit(PipelineEvent::PhaseStarted {
            phase: *phase,
            display_name: display_name.to_string(),
        });
    }

    fn emit_phase_completed(&self, phase: &PhaseName) {
        let display_name = PHASES
            .iter()
            .find(|p| p.name == *phase)
            .map(|p| p.display_name)
            .unwrap_or("Unknown");
        self.emit(PipelineEvent::PhaseCompleted {
            phase: *phase,
            display_name: display_name.to_string(),
        });
    }

    /// Accumulate new findings, emit FindingDiscovered events, and store them.
    async fn accumulate_findings(&self, new_findings: Vec<Finding>) {
        for f in &new_findings {
            self.emit(PipelineEvent::FindingDiscovered {
                title: f.title.clone(),
                severity: f.severity.clone(),
                category: format!("{:?}", f.category),
            });
        }
        self.findings.write().await.extend(new_findings);
    }

    /// Write all accumulated findings to deliverables files.
    async fn write_findings_to_deliverables(&self) -> Result<(), SekuraError> {
        let findings = self.findings.read().await;
        let deliverables_dir = self.config.deliverables_dir();

        // 1. Write findings.json
        let json = serde_json::to_string_pretty(&*findings)
            .map_err(|e| SekuraError::Internal(format!("Failed to serialize findings: {}", e)))?;
        let json_path = deliverables_dir.join("findings.json");
        tokio::fs::write(&json_path, &json).await?;
        info!(path = %json_path.display(), count = findings.len(), "Wrote findings.json");

        // 2. Write tool_findings_report.md
        if !findings.is_empty() {
            let mut report = String::new();
            report.push_str("# Tool Findings Report\n\n");
            report.push_str(&format_executive_summary(&findings));
            report.push_str("\n\n---\n\n");
            for finding in findings.iter() {
                report.push_str(&format_finding_markdown(finding));
                report.push_str("\n---\n\n");
            }
            let report_path = deliverables_dir.join("tool_findings_report.md");
            tokio::fs::write(&report_path, &report).await?;
            info!(path = %report_path.display(), "Wrote tool_findings_report.md");
        }

        // 3. Write per-category evidence files
        let mut by_category: HashMap<String, Vec<&Finding>> = HashMap::new();
        for f in findings.iter() {
            let key = match f.category {
                VulnCategory::Injection => "injection",
                VulnCategory::Xss => "xss",
                VulnCategory::Auth => "auth",
                VulnCategory::Ssrf => "ssrf",
                VulnCategory::Authz => "authz",
                VulnCategory::Infrastructure => "infrastructure",
            };
            by_category.entry(key.to_string()).or_default().push(f);
        }

        for (category, cat_findings) in &by_category {
            // Skip infrastructure for per-category files (it goes in the main report)
            if category == "infrastructure" {
                continue;
            }
            let filename = format!("{}_exploitation_evidence.md", category);
            let mut content = format!("# {} Findings\n\n", category.to_uppercase());
            for f in cat_findings {
                content.push_str(&format_finding_markdown(f));
                content.push_str("\n---\n\n");
            }
            let path = deliverables_dir.join(&filename);
            tokio::fs::write(&path, &content).await?;
            info!(path = %path.display(), count = cat_findings.len(), "Wrote category evidence file");
        }

        Ok(())
    }

    /// Compute a real PipelineSummary from accumulated findings and agent metrics.
    async fn compute_summary(&self) -> PipelineSummary {
        let findings = self.findings.read().await;
        let state = self.state.read().await;

        let mut finding_counts: HashMap<String, usize> = HashMap::new();
        for f in findings.iter() {
            *finding_counts.entry(format!("{:?}", f.severity)).or_insert(0) += 1;
        }

        let total_cost_usd: f64 = state.agent_metrics.values()
            .filter_map(|m| m.cost_usd)
            .sum();
        let total_duration_ms: u64 = state.start_time.signed_duration_since(chrono::Utc::now())
            .num_milliseconds()
            .unsigned_abs();

        PipelineSummary {
            total_cost_usd,
            total_duration_ms,
            total_findings: findings.len(),
            finding_counts,
            agent_count: state.completed_agents.len() + state.failed_agents.len(),
            phases_completed: state.completed_agents.len().min(5),
        }
    }

    pub async fn run(&self) -> Result<PipelineSummary, SekuraError> {
        self.update_status(PipelineStatus::Running).await;
        info!(scan_id = %self.config.scan_id, target = %self.config.target, "Pipeline started");

        // Ensure Kali container is running
        self.container.ensure_running().await?;

        // Build initial scan context
        let mut context = ScanContext::new(&self.config.target, self.config.intensity);
        if let Some(cookie) = &self.config.cookie {
            context.cookie_string = Some(cookie.clone());
            context.authenticated = true;
        }

        // Phase 1: White-box analysis
        if self.config.has_repo() && !self.config.skip_whitebox {
            self.check_cancelled()?;
            info!("Phase 1: White-box Analysis");
            self.set_phase(PhaseName::WhiteboxAnalysis).await;
            self.emit_phase_started(&PhaseName::WhiteboxAnalysis);
            // White-box analysis would run here
            self.emit_phase_completed(&PhaseName::WhiteboxAnalysis);
            info!("Phase 1 complete");
        }

        // Phase 2: Reconnaissance
        if !self.config.skip_blackbox {
            self.check_cancelled()?;
            info!("Phase 2: Reconnaissance");
            self.set_phase(PhaseName::Reconnaissance).await;
            self.emit_phase_started(&PhaseName::Reconnaissance);

            let runner = crate::techniques::runner::TechniqueRunner::new(
                self.container.clone(),
                context.clone(),
                self.llm.clone(),
            );

            // Run technique groups
            let layers = ["network", "ip", "tcp"];
            for layer in &layers {
                if let Some(techs) = self.technique_library.get_all_techniques_for_layer(layer) {
                    self.emit(PipelineEvent::TechniqueRunning {
                        technique_name: format!("{} scan", layer),
                        layer: layer.to_string(),
                    });
                    let (findings, outputs) = runner.run_techniques(techs).await?;
                    context.update_from_outputs(&outputs);
                    self.emit(PipelineEvent::TechniqueCompleted {
                        technique_name: format!("{} scan", layer),
                        findings_count: findings.len(),
                    });
                    info!(layer, findings = findings.len(), "Layer scan complete");
                    self.accumulate_findings(findings).await;
                }
            }

            let layers2 = ["presentation", "session", "application"];
            for layer in &layers2 {
                if let Some(techs) = self.technique_library.get_all_techniques_for_layer(layer) {
                    self.emit(PipelineEvent::TechniqueRunning {
                        technique_name: format!("{} scan", layer),
                        layer: layer.to_string(),
                    });
                    let (findings, outputs) = runner.run_techniques(techs).await?;
                    context.update_from_outputs(&outputs);
                    self.emit(PipelineEvent::TechniqueCompleted {
                        technique_name: format!("{} scan", layer),
                        findings_count: findings.len(),
                    });
                    info!(layer, findings = findings.len(), "Layer scan complete");
                    self.accumulate_findings(findings).await;
                }
            }

            if context.has_open_ports() {
                if let Some(techs) = self.technique_library.get_all_techniques_for_layer("exploitation") {
                    self.emit(PipelineEvent::TechniqueRunning {
                        technique_name: "exploitation techniques".to_string(),
                        layer: "exploitation".to_string(),
                    });
                    let (findings, _) = runner.run_techniques(techs).await?;
                    self.emit(PipelineEvent::TechniqueCompleted {
                        technique_name: "exploitation techniques".to_string(),
                        findings_count: findings.len(),
                    });
                    info!(findings = findings.len(), "Exploitation techniques complete");
                    self.accumulate_findings(findings).await;
                }
            }

            self.emit_phase_completed(&PhaseName::Reconnaissance);
            info!("Phase 2 complete");
        }

        // Phases 3-4: Vulnerability Analysis + Exploitation (pipelined)
        if !self.config.skip_exploit && !self.config.blackbox_only {
            self.check_cancelled()?;
            info!("Phases 3-4: Vulnerability Analysis & Exploitation");
            self.set_phase(PhaseName::VulnerabilityAnalysis).await;
            self.emit_phase_started(&PhaseName::VulnerabilityAnalysis);
            self.run_vuln_exploit_pipelines().await?;
            self.emit_phase_completed(&PhaseName::VulnerabilityAnalysis);
            self.emit_phase_started(&PhaseName::Exploitation);
            self.emit_phase_completed(&PhaseName::Exploitation);
            info!("Phases 3-4 complete");
        }

        // Write findings to deliverables before reporting phase
        self.write_findings_to_deliverables().await?;

        // Phase 5: Reporting
        self.check_cancelled()?;
        info!("Phase 5: Reporting");
        self.set_phase(PhaseName::Reporting).await;
        self.emit_phase_started(&PhaseName::Reporting);
        crate::reporting::assembler::assemble_final_report(&self.config.deliverables_dir()).await?;
        self.emit_phase_completed(&PhaseName::Reporting);
        info!("Phase 5 complete");

        let summary = self.compute_summary().await;
        {
            let mut state = self.state.write().await;
            state.summary = Some(summary.clone());
        }
        self.update_status(PipelineStatus::Completed).await;

        self.emit(PipelineEvent::PipelineCompleted {
            total_findings: summary.total_findings,
            total_cost_usd: summary.total_cost_usd,
            total_duration_ms: summary.total_duration_ms,
        });

        info!(scan_id = %self.config.scan_id, findings = summary.total_findings, "Pipeline completed");
        Ok(summary)
    }

    async fn run_vuln_exploit_pipelines(&self) -> Result<(), SekuraError> {
        use crate::queue::VulnType;
        let vuln_types = [
            VulnType::Injection,
            VulnType::Xss,
            VulnType::Auth,
            VulnType::Ssrf,
            VulnType::Authz,
        ];

        let handles: Vec<_> = vuln_types.iter().map(|vt| {
            let vt = *vt;
            let deliverables_dir = self.config.deliverables_dir();
            tokio::spawn(async move {
                let decision = crate::queue::validator::validate_queue_and_deliverable(
                    vt, &deliverables_dir,
                ).await;
                match decision {
                    Ok(d) if d.should_exploit => {
                        info!(vuln_type = %vt.as_str(), count = d.vulnerability_count, "Exploiting vulnerabilities");
                    }
                    Ok(_) => {
                        info!(vuln_type = %vt.as_str(), "No vulnerabilities to exploit");
                    }
                    Err(e) => {
                        warn!(vuln_type = %vt.as_str(), error = %e, "Queue validation failed");
                    }
                }
            })
        }).collect();

        let results = futures::future::join_all(handles).await;
        for (i, result) in results.iter().enumerate() {
            if let Err(e) = result {
                error!(vuln_type = ?vuln_types[i], error = %e, "Pipeline task panicked");
            }
        }

        Ok(())
    }

    async fn update_status(&self, status: PipelineStatus) {
        let mut state = self.state.write().await;
        state.status = status;
    }

    async fn set_phase(&self, phase: PhaseName) {
        let mut state = self.state.write().await;
        state.current_phase = Some(phase);
    }

    fn check_cancelled(&self) -> Result<(), SekuraError> {
        if self.cancel_token.is_cancelled() {
            Err(SekuraError::Internal("Pipeline cancelled".into()))
        } else {
            Ok(())
        }
    }

    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    pub fn state(&self) -> Arc<RwLock<PipelineState>> {
        self.state.clone()
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    pub fn findings(&self) -> Arc<RwLock<Vec<Finding>>> {
        self.findings.clone()
    }
}
