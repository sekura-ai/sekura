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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_config_passes() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            "target: https://example.com\nintensity: standard"
        ).unwrap();
        assert!(validate_security_patterns(&yaml).is_ok());
    }

    #[test]
    fn test_directory_traversal_blocked() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            "path: ../../etc/passwd"
        ).unwrap();
        assert!(validate_security_patterns(&yaml).is_err());
    }

    #[test]
    fn test_script_injection_blocked() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            "value: '<script>alert(1)</script>'"
        ).unwrap();
        assert!(validate_security_patterns(&yaml).is_err());
    }

    #[test]
    fn test_javascript_uri_blocked() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            "url: 'javascript:void(0)'"
        ).unwrap();
        assert!(validate_security_patterns(&yaml).is_err());
    }

    #[test]
    fn test_data_uri_blocked() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            "url: 'data:text/html,<h1>hi</h1>'"
        ).unwrap();
        assert!(validate_security_patterns(&yaml).is_err());
    }

    #[test]
    fn test_file_uri_blocked() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            "url: 'file:///etc/passwd'"
        ).unwrap();
        assert!(validate_security_patterns(&yaml).is_err());
    }

    #[test]
    fn test_nested_dangerous_pattern_blocked() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            "rules:\n  avoid:\n    - path: '../../secret'"
        ).unwrap();
        assert!(validate_security_patterns(&yaml).is_err());
    }

    #[test]
    fn test_array_dangerous_pattern_blocked() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            "items:\n  - '<script>alert(1)'"
        ).unwrap();
        assert!(validate_security_patterns(&yaml).is_err());
    }

    #[test]
    fn test_numeric_values_pass() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            "port: 8080\nenabled: true"
        ).unwrap();
        assert!(validate_security_patterns(&yaml).is_ok());
    }
}
