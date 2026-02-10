use std::collections::HashMap;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use console::style;
use crate::repl::events::PipelineEvent;

/// Manages indicatif multi-progress bars during pipeline execution.
pub struct ScanProgress {
    multi: MultiProgress,
    phase_bar: Option<ProgressBar>,
    technique_bars: HashMap<String, ProgressBar>,
    status_bar: ProgressBar,
    findings_count: usize,
    cost_usd: f64,
    start_time: std::time::Instant,
}

const PHASE_COUNT: u64 = 5;

impl ScanProgress {
    pub fn new() -> Self {
        let multi = MultiProgress::new();

        // Status bar at the bottom showing elapsed / cost / findings
        let status_bar = multi.add(ProgressBar::new_spinner());
        status_bar.set_style(
            ProgressStyle::default_spinner()
                .template("  {spinner:.cyan} {msg}")
                .unwrap()
        );
        status_bar.set_message("Initializing scan...");
        status_bar.enable_steady_tick(std::time::Duration::from_millis(120));

        Self {
            multi,
            phase_bar: None,
            technique_bars: HashMap::new(),
            status_bar,
            findings_count: 0,
            cost_usd: 0.0,
            start_time: std::time::Instant::now(),
        }
    }

    /// Handle a pipeline event and update progress bars accordingly.
    pub fn handle_event(&mut self, event: &PipelineEvent) {
        match event {
            PipelineEvent::PipelineStarted { target, .. } => {
                let bar = self.multi.insert_before(
                    &self.status_bar,
                    ProgressBar::new(PHASE_COUNT),
                );
                bar.set_style(
                    ProgressStyle::default_bar()
                        .template("  {bar:30.cyan/dark_gray} {pos}/{len} phases | {msg}")
                        .unwrap()
                        .progress_chars("█▓░")
                );
                bar.set_message(format!("Scanning {}", target));
                self.phase_bar = Some(bar);
                self.update_status();
            }
            PipelineEvent::PhaseStarted { display_name, .. } => {
                if let Some(bar) = &self.phase_bar {
                    bar.set_message(display_name.clone());
                }
                self.update_status();
            }
            PipelineEvent::PhaseCompleted { .. } => {
                if let Some(bar) = &self.phase_bar {
                    bar.inc(1);
                }
            }
            PipelineEvent::TechniqueRunning { technique_name, layer } => {
                let bar = self.multi.insert_before(
                    &self.status_bar,
                    ProgressBar::new_spinner(),
                );
                bar.set_style(
                    ProgressStyle::default_spinner()
                        .template("    {spinner:.yellow} {msg}")
                        .unwrap()
                );
                bar.set_message(format!("{} ({})", technique_name, layer));
                bar.enable_steady_tick(std::time::Duration::from_millis(100));
                self.technique_bars.insert(technique_name.clone(), bar);
            }
            PipelineEvent::TechniqueCompleted { technique_name, .. } => {
                if let Some(bar) = self.technique_bars.remove(technique_name) {
                    bar.finish_and_clear();
                }
            }
            PipelineEvent::FindingDiscovered { .. } => {
                self.findings_count += 1;
                self.update_status();
            }
            PipelineEvent::AgentCompleted { cost_usd, .. } => {
                if let Some(c) = cost_usd {
                    self.cost_usd += c;
                    self.update_status();
                }
            }
            PipelineEvent::PipelineCompleted { total_findings, total_cost_usd, total_duration_ms } => {
                // Clear all active bars
                for (_, bar) in self.technique_bars.drain() {
                    bar.finish_and_clear();
                }
                if let Some(bar) = self.phase_bar.take() {
                    bar.finish_with_message("All phases complete");
                }
                self.status_bar.finish_with_message(format!(
                    "Scan complete: {} findings | ${:.4} | {}",
                    total_findings,
                    total_cost_usd,
                    format_elapsed(*total_duration_ms),
                ));
            }
            PipelineEvent::CostWarning { current_usd, max_usd } => {
                let pct = (current_usd / max_usd) * 100.0;
                self.println(&format!(
                    "  {} Cost warning: ${:.4} / ${:.4} ({:.0}% of budget)",
                    style("⚠").yellow(), current_usd, max_usd, pct
                ));
            }
            PipelineEvent::PipelineFailed { error } => {
                for (_, bar) in self.technique_bars.drain() {
                    bar.finish_and_clear();
                }
                if let Some(bar) = self.phase_bar.take() {
                    bar.abandon_with_message("Failed");
                }
                self.status_bar.finish_with_message(format!("Scan failed: {}", error));
            }
            _ => {}
        }
    }

    fn update_status(&self) {
        let elapsed = self.start_time.elapsed();
        let elapsed_str = format_elapsed(elapsed.as_millis() as u64);
        self.status_bar.set_message(format!(
            "{} | ${:.4} | {} findings",
            elapsed_str, self.cost_usd, self.findings_count,
        ));
    }

    /// Get the MultiProgress for integration with rustyline's ExternalPrinter.
    pub fn multi(&self) -> &MultiProgress {
        &self.multi
    }

    /// Print a line through the multi-progress (won't interfere with bars).
    pub fn println(&self, msg: &str) {
        let _ = self.multi.println(msg);
    }
}

fn format_elapsed(ms: u64) -> String {
    let secs = ms / 1000;
    let mins = secs / 60;
    let remaining_secs = secs % 60;
    if mins > 0 {
        format!("{}m{}s", mins, remaining_secs)
    } else {
        format!("{}s", secs)
    }
}
