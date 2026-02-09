use crate::errors::SekuraError;

const DANGEROUS_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "<script",
    "javascript:",
    "data:",
    "file:",
    "vbscript:",
];

pub fn validate_security_patterns(value: &serde_yaml::Value) -> Result<(), SekuraError> {
    check_value(value, &[])?;
    Ok(())
}

fn check_value(value: &serde_yaml::Value, path: &[String]) -> Result<(), SekuraError> {
    match value {
        serde_yaml::Value::String(s) => {
            let lower = s.to_lowercase();
            for pattern in DANGEROUS_PATTERNS {
                if lower.contains(pattern) {
                    let path_str = if path.is_empty() { "root".to_string() } else { path.join(".") };
                    return Err(SekuraError::Config(
                        format!("Dangerous pattern '{}' found at config path: {}", pattern, path_str)
                    ));
                }
            }
            Ok(())
        }
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let key = k.as_str().unwrap_or("unknown").to_string();
                let mut new_path = path.to_vec();
                new_path.push(key);
                check_value(v, &new_path)?;
            }
            Ok(())
        }
        serde_yaml::Value::Sequence(seq) => {
            for (i, v) in seq.iter().enumerate() {
                let mut new_path = path.to_vec();
                new_path.push(format!("[{}]", i));
                check_value(v, &new_path)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
