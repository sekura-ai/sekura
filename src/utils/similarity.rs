pub fn is_similar(a: &str, b: &str, threshold: f64) -> bool {
    if a == b { return true; }
    if a.is_empty() || b.is_empty() { return false; }

    let ratio = similarity_ratio(a, b);
    ratio >= threshold
}

fn similarity_ratio(a: &str, b: &str) -> f64 {
    let a_lines: Vec<&str> = a.lines().collect();
    let b_lines: Vec<&str> = b.lines().collect();

    if a_lines.is_empty() && b_lines.is_empty() { return 1.0; }

    let common = a_lines.iter().filter(|l| b_lines.contains(l)).count();
    let total = a_lines.len().max(b_lines.len());

    if total == 0 { return 1.0; }
    common as f64 / total as f64
}
