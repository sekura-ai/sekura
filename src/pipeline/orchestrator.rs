use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use crate::audit::{AuditSession, AuditEvent};
use crate::container::ContainerManager;
use crate::errors::SekuraError;
use crate::llm;
use crate::llm::provider::LLMProvider;
use crate::models::finding::{Finding, VulnCategory};
use crate::prompts::PromptLoader;
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
    prompt_loader: Arc<PromptLoader>,
    event_tx: Option<mpsc::UnboundedSender<PipelineEvent>>,
    findings: Arc<RwLock<Vec<Finding>>>,
    audit: Arc<AuditSession>,
}

impl PipelineOrchestrator {
    pub async fn new(config: PipelineConfig) -> Result<Self, SekuraError> {
        // Create output directories
        tokio::fs::create_dir_all(config.deliverables_dir()).await?;
        tokio::fs::create_dir_all(config.audit_dir()).await?;

        // Initialize crash-safe audit session
        let audit = Arc::new(
            AuditSession::initialize(&config.output_dir, &config.scan_id).await?
        );

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

        // Initialize prompt loader
        let prompts_dir = std::env::current_dir()?.join("prompts");
        let prompt_loader = Arc::new(PromptLoader::new(prompts_dir));

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(PipelineState::new())),
            cancel_token: CancellationToken::new(),
            container,
            llm,
            technique_library,
            prompt_loader,
            event_tx: None,
            findings: Arc::new(RwLock::new(Vec::new())),
            audit,
        })
    }

    /// Replace the orchestrator's cancel token with an external one (e.g. from the REPL session).
    /// This ensures that calling `.cancel()` on the external token actually stops the pipeline.
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
        self
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
            self.audit.record_event(AuditEvent::FindingDiscovered {
                title: f.title.clone(),
                severity: format!("{:?}", f.severity),
                category: format!("{:?}", f.category),
            }).await;
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

    /// Compute WSTG coverage based on executed techniques and write to deliverables.
    async fn write_wstg_coverage(&self) {
        use std::collections::HashSet;
        let techniques_dir = match std::env::current_dir() {
            Ok(d) => d.join("techniques"),
            Err(_) => return,
        };

        // Collect all technique names that appear in findings as executed
        let findings = self.findings.read().await;
        let mut executed: HashSet<String> = HashSet::new();
        for f in findings.iter() {
            executed.insert(f.technique.clone());
        }

        // Also add standard techniques we know ran based on the layers we iterated
        let all_layers = self.technique_library.available_layers();
        for layer in &all_layers {
            if let Some(techs) = self.technique_library.get_all_techniques_for_layer(layer) {
                for t in techs {
                    executed.insert(t.name.clone());
                }
            }
        }

        match crate::techniques::wstg::compute_wstg_coverage(&techniques_dir, &executed) {
            Ok(coverage) => {
                let md = crate::techniques::wstg::format_wstg_coverage_markdown(&coverage);
                let path = self.config.deliverables_dir().join("wstg_coverage_report.md");
                if let Err(e) = tokio::fs::write(&path, &md).await {
                    warn!(error = %e, "Failed to write WSTG coverage report");
                } else {
                    info!(
                        coverage_pct = format!("{:.1}%", coverage.total_coverage_pct),
                        "WSTG coverage report written"
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to compute WSTG coverage");
            }
        }
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

        // Record scan start in audit trail
        self.audit.record_scan_started(
            &self.config.target,
            &format!("{}", self.config.intensity),
            &self.config.provider,
        ).await;

        // Ensure Kali container is running
        self.container.ensure_running().await?;

        // Build initial scan context
        let mut context = ScanContext::new(&self.config.target, self.config.intensity);
        if let Some(cookie) = &self.config.cookie {
            context.cookie_string = Some(cookie.clone());
            context.authenticated = true;
        }

        // Pre-flight: warn if repo has uncommitted changes
        if self.config.has_repo() {
            if let Some(warning) = crate::git::check_repo_clean(&self.config.repo_path) {
                warn!("{}", warning);
                self.audit.record_event(AuditEvent::Warning {
                    message: warning,
                }).await;
            }
        }

        // Phase 1: White-box analysis
        if self.config.has_repo() && !self.config.skip_whitebox {
            self.check_cancelled().await?;
            info!("Phase 1: White-box Analysis");
            self.set_phase(PhaseName::WhiteboxAnalysis).await;
            self.emit_phase_started(&PhaseName::WhiteboxAnalysis);
            // White-box analysis would run here
            self.emit_phase_completed(&PhaseName::WhiteboxAnalysis);
            info!("Phase 1 complete");
        }

        // Phase 2: Reconnaissance
        if !self.config.skip_blackbox {
            self.check_cancelled().await?;
            self.check_cost_budget().await?;
            info!("Phase 2: Reconnaissance");
            self.set_phase(PhaseName::Reconnaissance).await;
            self.emit_phase_started(&PhaseName::Reconnaissance);

            let scope = crate::techniques::runner::ScopeRules::from_config(
                self.config.rules_avoid.as_deref(),
                self.config.rules_focus.as_deref(),
            );
            let mut runner_builder = crate::techniques::runner::TechniqueRunner::new(
                self.container.clone(),
                context.clone(),
                self.llm.clone(),
                self.prompt_loader.clone(),
            ).with_scope(scope)
             .with_dry_run(self.config.pipeline_testing)
             .with_audit(self.audit.clone())
             .with_cancel_token(self.cancel_token.clone());

            if let Some(ref tx) = self.event_tx {
                runner_builder = runner_builder.with_event_channel(tx.clone());
            }
            let runner = runner_builder;

            // Run technique groups — per-technique events emitted by the runner
            let layers = ["network", "ip", "tcp"];
            for layer in &layers {
                self.check_cancelled().await?;
                if let Some(techs) = self.technique_library.get_all_techniques_for_layer(layer) {
                    let (findings, outputs) = runner.run_techniques(techs, layer).await?;
                    context.update_from_outputs(&outputs);
                    info!(layer, findings = findings.len(), "Layer scan complete");
                    self.accumulate_findings(findings).await;
                }
            }

            let layers2 = ["presentation", "session", "application"];
            for layer in &layers2 {
                self.check_cancelled().await?;
                if let Some(techs) = self.technique_library.get_all_techniques_for_layer(layer) {
                    let (findings, outputs) = runner.run_techniques(techs, layer).await?;
                    context.update_from_outputs(&outputs);
                    info!(layer, findings = findings.len(), "Layer scan complete");
                    self.accumulate_findings(findings).await;
                }
            }

            if context.has_open_ports() {
                if let Some(techs) = self.technique_library.get_all_techniques_for_layer("exploitation") {
                    let (findings, _) = runner.run_techniques(techs, "exploitation").await?;
                    info!(findings = findings.len(), "Exploitation techniques complete");
                    self.accumulate_findings(findings).await;
                }
            }

            self.emit_phase_completed(&PhaseName::Reconnaissance);
            info!("Phase 2 complete");
        }

        // Phases 3-4: Vulnerability Analysis + Exploitation (pipelined)
        if !self.config.skip_exploit && !self.config.blackbox_only {
            self.check_cancelled().await?;
            self.check_cost_budget().await?;
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

        // Compute and write WSTG coverage report
        self.write_wstg_coverage().await;

        // Phase 5: Reporting
        self.check_cancelled().await?;
        self.check_cost_budget().await?;
        info!("Phase 5: Reporting");
        self.set_phase(PhaseName::Reporting).await;
        self.emit_phase_started(&PhaseName::Reporting);
        crate::reporting::assembler::assemble_final_report(
            &self.config.deliverables_dir(),
            self.llm.as_ref(),
            &self.prompt_loader,
            &self.config.target,
        ).await?;
        self.emit_phase_completed(&PhaseName::Reporting);
        info!("Phase 5 complete");

        let summary = self.compute_summary().await;
        {
            let mut state = self.state.write().await;
            state.summary = Some(summary.clone());
        }
        self.update_status(PipelineStatus::Completed).await;

        // Write session metrics summary to deliverables
        self.write_session_metrics(&summary).await;

        self.emit(PipelineEvent::PipelineCompleted {
            total_findings: summary.total_findings,
            total_cost_usd: summary.total_cost_usd,
            total_duration_ms: summary.total_duration_ms,
        });

        // Record scan completion in audit trail
        self.audit.record_event(AuditEvent::ScanCompleted {
            total_findings: summary.total_findings,
            total_cost_usd: summary.total_cost_usd,
            total_duration_ms: summary.total_duration_ms,
        }).await;

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

        // Build a shared ScanContext snapshot for the vuln agents
        let context = ScanContext {
            target: self.config.target.clone(),
            target_url: Some(self.config.target.clone()),
            intensity: self.config.intensity,
            ..Default::default()
        };

        // Spawn 5 concurrent vuln → exploit pipelines
        let handles: Vec<_> = vuln_types.iter().map(|vt| {
            let vt = *vt;
            let llm = self.llm.clone();
            let prompt_loader = self.prompt_loader.clone();
            let config = self.config.clone();
            let context = context.clone();
            let findings_acc = self.findings.clone();
            let event_tx = self.event_tx.clone();

            tokio::spawn(async move {
                // Phase 3: Vulnerability Analysis
                info!(vuln_type = %vt.as_str(), "Starting vuln analysis pipeline");
                let vuln_agent_name = format!("{} vulnerability analysis", vt.as_str());
                if let Some(ref tx) = event_tx {
                    let _ = tx.send(PipelineEvent::TechniqueRunning {
                        technique_name: vuln_agent_name.clone(),
                        layer: "vulnerability-analysis".to_string(),
                    });
                }

                let vuln_start = std::time::Instant::now();
                let vuln_result = crate::agents::vuln::run_vuln_analysis(
                    vt, llm.clone(), prompt_loader.clone(), &config, &context,
                ).await;

                let (queue, vuln_findings, vuln_cost) = match vuln_result {
                    Ok(result) => result,
                    Err(e) => {
                        warn!(vuln_type = %vt.as_str(), error = %e, "Vuln analysis failed");
                        if let Some(ref tx) = event_tx {
                            let _ = tx.send(PipelineEvent::AgentFailed {
                                agent_name: vuln_agent_name.clone(),
                                error: e.to_string(),
                            });
                            let _ = tx.send(PipelineEvent::TechniqueCompleted {
                                technique_name: vuln_agent_name,
                                findings_count: 0,
                            });
                        }
                        return;
                    }
                };
                let vuln_duration_ms = vuln_start.elapsed().as_millis() as u64;

                // Emit AgentCompleted with cost for the progress bar
                if let Some(ref tx) = event_tx {
                    let _ = tx.send(PipelineEvent::AgentCompleted {
                        agent_name: vuln_agent_name.clone(),
                        duration_ms: vuln_duration_ms,
                        cost_usd: vuln_cost,
                    });
                }

                // Accumulate vuln analysis findings
                {
                    let mut acc = findings_acc.write().await;
                    for f in &vuln_findings {
                        if let Some(ref tx) = event_tx {
                            let _ = tx.send(PipelineEvent::FindingDiscovered {
                                title: f.title.clone(),
                                severity: f.severity.clone(),
                                category: format!("{:?}", f.category),
                            });
                        }
                    }
                    acc.extend(vuln_findings);
                }

                if let Some(ref tx) = event_tx {
                    let _ = tx.send(PipelineEvent::TechniqueCompleted {
                        technique_name: vuln_agent_name,
                        findings_count: queue.vulnerabilities.len(),
                    });
                }

                // Phase 4: Exploitation
                info!(vuln_type = %vt.as_str(), queue_size = queue.vulnerabilities.len(), "Starting exploitation pipeline");
                let exploit_agent_name = format!("{} exploitation", vt.as_str());
                if let Some(ref tx) = event_tx {
                    let _ = tx.send(PipelineEvent::TechniqueRunning {
                        technique_name: exploit_agent_name.clone(),
                        layer: "exploitation".to_string(),
                    });
                }

                let exploit_start = std::time::Instant::now();
                let exploit_result = crate::agents::exploit::run_exploitation(
                    vt, &queue, llm, prompt_loader, &config,
                ).await;

                match exploit_result {
                    Ok((exploit_findings, exploit_cost)) => {
                        let exploit_duration_ms = exploit_start.elapsed().as_millis() as u64;
                        let count = exploit_findings.len();

                        // Emit AgentCompleted with cost
                        if let Some(ref tx) = event_tx {
                            let _ = tx.send(PipelineEvent::AgentCompleted {
                                agent_name: exploit_agent_name.clone(),
                                duration_ms: exploit_duration_ms,
                                cost_usd: exploit_cost,
                            });
                        }

                        let mut acc = findings_acc.write().await;
                        for f in &exploit_findings {
                            if let Some(ref tx) = event_tx {
                                let _ = tx.send(PipelineEvent::FindingDiscovered {
                                    title: f.title.clone(),
                                    severity: f.severity.clone(),
                                    category: format!("{:?}", f.category),
                                });
                            }
                        }
                        acc.extend(exploit_findings);
                        info!(vuln_type = %vt.as_str(), findings = count, "Exploitation complete");
                    }
                    Err(e) => {
                        warn!(vuln_type = %vt.as_str(), error = %e, "Exploitation failed");
                        if let Some(ref tx) = event_tx {
                            let _ = tx.send(PipelineEvent::AgentFailed {
                                agent_name: exploit_agent_name.clone(),
                                error: e.to_string(),
                            });
                        }
                    }
                }

                if let Some(ref tx) = event_tx {
                    let _ = tx.send(PipelineEvent::TechniqueCompleted {
                        technique_name: exploit_agent_name,
                        findings_count: 0,
                    });
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

    async fn check_cancelled(&self) -> Result<(), SekuraError> {
        if self.cancel_token.is_cancelled() {
            self.update_status(PipelineStatus::Failed).await;
            self.audit.record_event(AuditEvent::ScanFailed {
                error: "Pipeline cancelled by user".to_string(),
            }).await;
            self.emit(PipelineEvent::PipelineFailed {
                error: "Pipeline cancelled by user".to_string(),
            });
            info!("Pipeline cancelled by user");
            Err(SekuraError::Internal("Pipeline cancelled by user".into()))
        } else {
            Ok(())
        }
    }

    /// Check if the cost budget has been exceeded. Returns Err if over budget.
    /// Emits a warning at 80% utilization.
    async fn check_cost_budget(&self) -> Result<(), SekuraError> {
        if let Some(max_cost) = self.config.max_cost {
            let current = self.audit.cumulative_cost().await;
            if current >= max_cost {
                warn!(current_cost = current, max_cost = max_cost, "Cost budget exceeded — aborting pipeline");
                self.audit.record_event(AuditEvent::Warning {
                    message: format!("Cost budget exceeded: ${:.4} >= ${:.4}", current, max_cost),
                }).await;
                return Err(SekuraError::Internal(format!(
                    "Cost budget exceeded: ${:.4} of ${:.4} limit",
                    current, max_cost
                )));
            }
            let threshold = max_cost * 0.8;
            if current >= threshold {
                warn!(
                    current_cost = current,
                    budget_pct = format!("{:.0}%", (current / max_cost) * 100.0),
                    "Cost budget at 80%+ utilization"
                );
                self.emit(PipelineEvent::CostWarning {
                    current_usd: current,
                    max_usd: max_cost,
                });
            }
        }
        Ok(())
    }

    /// Write session metrics summary as JSON to deliverables.
    async fn write_session_metrics(&self, summary: &PipelineSummary) {
        let metrics = serde_json::json!({
            "scan_id": self.config.scan_id,
            "target": self.config.target,
            "intensity": format!("{}", self.config.intensity),
            "provider": self.config.provider,
            "model": self.config.model,
            "total_findings": summary.total_findings,
            "finding_counts": summary.finding_counts,
            "total_cost_usd": summary.total_cost_usd,
            "total_duration_ms": summary.total_duration_ms,
            "phases_completed": summary.phases_completed,
            "agent_count": summary.agent_count,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        let path = self.config.deliverables_dir().join("session_metrics.json");
        match serde_json::to_string_pretty(&metrics) {
            Ok(json) => {
                if let Err(e) = tokio::fs::write(&path, &json).await {
                    warn!(error = %e, "Failed to write session metrics");
                } else {
                    info!(path = %path.display(), "Session metrics written");
                }
            }
            Err(e) => warn!(error = %e, "Failed to serialize session metrics"),
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

    pub fn audit(&self) -> Arc<AuditSession> {
        self.audit.clone()
    }
}
