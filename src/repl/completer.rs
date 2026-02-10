use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

use crate::repl::commands::COMMAND_NAMES;

#[derive(Default)]
pub struct ReplHelper;

impl Helper for ReplHelper {}
impl Validator for ReplHelper {}
impl Highlighter for ReplHelper {}

impl Hinter for ReplHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        if pos < line.len() {
            return None;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with('/') || trimmed.contains(' ') {
            return None;
        }
        for name in COMMAND_NAMES {
            if name.starts_with(trimmed) && *name != trimmed {
                return Some(name[trimmed.len()..].to_string());
            }
        }
        None
    }
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // Only complete the first token (the command name)
        let prefix = &line[..pos];
        let trimmed = prefix.trim_start();

        if !trimmed.starts_with('/') {
            return Ok((0, vec![]));
        }

        // If there's a space, we're past the command name -- complete flags
        if let Some(space_idx) = trimmed.find(' ') {
            let cmd = &trimmed[..space_idx];
            let flag_prefix = trimmed[space_idx..].trim_start();
            let flag_start = pos - flag_prefix.len();

            let flags: &[&str] = match cmd {
                "/scan" => &[
                    "--target", "--repo", "--intensity", "--provider", "--model",
                    "--skip-whitebox", "--skip-blackbox", "--skip-exploit",
                ],
                "/findings" => &["--severity"],
                "/report" => &["findings", "finding", "executive", "evidence", "full", "html", "--scan"],
                "/serve" => &["--port"],
                "/container" => &["status", "start", "stop", "rebuild"],
                _ => &[],
            };

            let matches: Vec<Pair> = flags
                .iter()
                .filter(|f| f.starts_with(flag_prefix))
                .map(|f| Pair {
                    display: f.to_string(),
                    replacement: f.to_string(),
                })
                .collect();

            return Ok((flag_start, matches));
        }

        // Complete command names
        let start = pos - trimmed.len();
        let matches: Vec<Pair> = COMMAND_NAMES
            .iter()
            .filter(|name| name.starts_with(trimmed))
            .map(|name| Pair {
                display: name.to_string(),
                replacement: name.to_string(),
            })
            .collect();

        Ok((start, matches))
    }
}
