const MAX_OUTPUT_LENGTH: usize = 15_000;
const MAX_ERROR_LENGTH: usize = 2_000;

pub fn truncate_output(output: &str) -> String {
    if output.len() <= MAX_OUTPUT_LENGTH {
        output.to_string()
    } else {
        let half = MAX_OUTPUT_LENGTH / 2;
        let start = &output[..half];
        let end = &output[output.len() - half..];
        format!("{}\n\n... [truncated {} chars] ...\n\n{}", start, output.len() - MAX_OUTPUT_LENGTH, end)
    }
}

pub fn truncate_error(error: &str) -> String {
    if error.len() <= MAX_ERROR_LENGTH {
        error.to_string()
    } else {
        format!("{}...", &error[..MAX_ERROR_LENGTH])
    }
}
