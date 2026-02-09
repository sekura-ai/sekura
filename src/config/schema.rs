use serde_json::{json, Value};
use std::sync::LazyLock;

pub static CONFIG_SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "authentication": {
                "type": "object",
                "properties": {
                    "login_type": { "type": "string", "enum": ["form", "sso", "api", "basic"] },
                    "login_url": { "type": "string", "format": "uri" },
                    "credentials": {
                        "type": "object",
                        "properties": {
                            "username": { "type": "string" },
                            "password": { "type": "string" },
                            "totp_secret": { "type": "string" }
                        }
                    }
                }
            },
            "rules": {
                "type": "object",
                "properties": {
                    "avoid": { "type": "array", "items": { "$ref": "#/$defs/rule" } },
                    "focus": { "type": "array", "items": { "$ref": "#/$defs/rule" } }
                }
            },
            "scan": {
                "type": "object",
                "properties": {
                    "intensity": { "type": "string", "enum": ["quick", "standard", "thorough"] },
                    "layers": { "type": "array", "items": { "type": "string" } },
                    "max_agent_iterations": { "type": "integer", "minimum": 1 },
                    "parallel_phases": { "type": "boolean" }
                }
            },
            "llm": {
                "type": "object",
                "properties": {
                    "provider": { "type": "string" },
                    "model": { "type": "string" },
                    "api_key": { "type": "string" },
                    "base_url": { "type": "string" }
                }
            },
            "container": {
                "type": "object",
                "properties": {
                    "image": { "type": "string" },
                    "name": { "type": "string" },
                    "network_mode": { "type": "string" },
                    "capabilities": { "type": "array", "items": { "type": "string" } }
                }
            },
            "output": {
                "type": "object",
                "properties": {
                    "directory": { "type": "string" },
                    "format": { "type": "string" }
                }
            }
        },
        "$defs": {
            "rule": {
                "type": "object",
                "required": ["description", "type", "url_path"],
                "properties": {
                    "description": { "type": "string" },
                    "type": { "type": "string", "enum": ["path", "subdomain", "domain", "method", "header", "parameter"] },
                    "url_path": { "type": "string" }
                }
            }
        }
    })
});
