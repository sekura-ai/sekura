pub fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        format!("{}m {}s", mins, secs)
    } else {
        let hours = ms / 3_600_000;
        let mins = (ms % 3_600_000) / 60_000;
        format!("{}h {}m", hours, mins)
    }
}

pub fn format_cost(usd: f64) -> String {
    let usd = usd.abs(); // avoid negative zero display
    if usd < 0.01 {
        format!("${:.4}", usd)
    } else {
        format!("${:.2}", usd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration_ms() {
        assert_eq!(format_duration(500), "500ms");
        assert_eq!(format_duration(0), "0ms");
        assert_eq!(format_duration(999), "999ms");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(1000), "1.0s");
        assert_eq!(format_duration(1500), "1.5s");
        assert_eq!(format_duration(59999), "60.0s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(60_000), "1m 0s");
        assert_eq!(format_duration(90_000), "1m 30s");
        assert_eq!(format_duration(3_599_999), "59m 59s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3_600_000), "1h 0m");
        assert_eq!(format_duration(5_400_000), "1h 30m");
    }

    #[test]
    fn test_format_cost_small() {
        let result = format_cost(0.0012);
        assert_eq!(result, "$0.0012");
    }

    #[test]
    fn test_format_cost_large() {
        let result = format_cost(1.50);
        assert_eq!(result, "$1.50");
    }

    #[test]
    fn test_format_cost_boundary() {
        assert_eq!(format_cost(0.0099), "$0.0099");
        assert_eq!(format_cost(0.01), "$0.01");
    }

    #[test]
    fn test_format_cost_negative() {
        assert_eq!(format_cost(-0.05), "$0.05");
    }

    #[test]
    fn test_format_cost_zero() {
        assert_eq!(format_cost(0.0), "$0.0000");
    }
}
