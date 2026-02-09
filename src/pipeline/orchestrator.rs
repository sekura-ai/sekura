use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use crate::config::ContainerConfig;
use crate::container::ContainerManager;
use crate::errors::SekuraError;
use crate::llm;
use crate::llm::provider::LLMProvider;
use crate::techniques::TechniqueLibrary;
use super::state::*;
use tracing::{info, warn, error};

pub struct PipelineOrchestrator {
    config: PipelineConfig,
    state: Arc<RwLock<PipelineState>>,
    cancel_token: CancellationToken,
    container: Arc<ContainerManager>,
    llm: Arc<dyn LLMProvider>,
    technique_library: Arc<TechniqueLibrary>,
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
        })
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
            // White-box analysis would run here
            info!("Phase 1 complete");
        }

        // Phase 2: Reconnaissance
        if !self.config.skip_blackbox {
            self.check_cancelled()?;
            info!("Phase 2: Reconnaissance");
            self.set_phase(PhaseName::Reconnaissance).await;

            let runner = crate::techniques::runner::TechniqueRunner::new(
                self.container.clone(),
                context.clone(),
            );

            // Run technique groups
            let layers = ["network", "ip", "tcp"];
            for layer in &layers {
                if let Some(techs) = self.technique_library.get_all_techniques_for_layer(layer) {
                    let (findings, outputs) = runner.run_techniques(techs).await?;
                    context.update_from_outputs(&outputs);
                    info!(layer, findings = findings.len(), "Layer scan complete");
                }
            }

            let layers2 = ["presentation", "session", "application"];
            for layer in &layers2 {
                if let Some(techs) = self.technique_library.get_all_techniques_for_layer(layer) {
                    let (findings, outputs) = runner.run_techniques(techs).await?;
                    context.update_from_outputs(&outputs);
                    info!(layer, findings = findings.len(), "Layer scan complete");
                }
            }

            if context.has_open_ports() {
                if let Some(techs) = self.technique_library.get_all_techniques_for_layer("exploitation") {
                    let (findings, _) = runner.run_techniques(techs).await?;
                    info!(findings = findings.len(), "Exploitation techniques complete");
                }
            }

            info!("Phase 2 complete");
        }

        // Phases 3-4: Vulnerability Analysis + Exploitation (pipelined)
        if !self.config.skip_exploit && !self.config.blackbox_only {
            self.check_cancelled()?;
            info!("Phases 3-4: Vulnerability Analysis & Exploitation");
            self.set_phase(PhaseName::VulnerabilityAnalysis).await;
            self.run_vuln_exploit_pipelines().await?;
            info!("Phases 3-4 complete");
        }

        // Phase 5: Reporting
        self.check_cancelled()?;
        info!("Phase 5: Reporting");
        self.set_phase(PhaseName::Reporting).await;
        crate::reporting::assembler::assemble_final_report(&self.config.deliverables_dir()).await?;
        info!("Phase 5 complete");

        let summary = PipelineSummary::default();
        self.update_status(PipelineStatus::Completed).await;
        info!(scan_id = %self.config.scan_id, "Pipeline completed");
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
}
