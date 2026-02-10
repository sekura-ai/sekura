use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use crate::config::Intensity;
use crate::errors::SekuraError;
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
pub struct TechniqueDefinition {
    pub name: String,
    pub tool: String,
    pub command: String,
    pub description: String,
    pub intensity: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    pub parse_hint: Option<String>,
    pub depends_on: Option<String>,
    pub depends_on_ports: Option<Vec<u16>>,
}

fn default_timeout() -> u64 {
    300
}

impl TechniqueDefinition {
    pub fn intensity_level(&self) -> u8 {
        match self.intensity.as_str() {
            "quick" => 0,
            "standard" => 1,
            "thorough" => 2,
            _ => 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LayerDefinition {
    pub layer: String,
    pub techniques: Vec<TechniqueDefinition>,
}

pub struct TechniqueLibrary {
    layers: HashMap<String, LayerDefinition>,
}

impl TechniqueLibrary {
    pub fn load(techniques_dir: &Path) -> Result<Self, SekuraError> {
        let mut layers = HashMap::new();

        if !techniques_dir.exists() {
            return Ok(Self { layers });
        }

        let pattern = techniques_dir.join("*.yaml");
        let pattern_str = pattern.to_string_lossy();

        for entry in glob::glob(&pattern_str)
            .map_err(|e| SekuraError::Config(format!("Invalid glob pattern: {}", e)))?
        {
            let path = entry.map_err(|e| SekuraError::Config(format!("Glob error: {}", e)))?;

            // Skip non-technique YAML files (e.g. wstg-mapping.yaml)
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if stem.starts_with("wstg-") || stem.starts_with("benchmark") {
                    continue;
                }
            }

            let content = std::fs::read_to_string(&path)?;
            let layer_def: LayerDefinition = serde_yaml::from_str(&content)?;
            info!(layer = %layer_def.layer, techniques = layer_def.techniques.len(), "Loaded technique layer");
            layers.insert(layer_def.layer.clone(), layer_def);
        }

        Ok(Self { layers })
    }

    pub fn get_techniques(
        &self,
        layer: &str,
        intensity: &Intensity,
    ) -> Result<Vec<&TechniqueDefinition>, SekuraError> {
        let layer_def = self.layers.get(layer)
            .ok_or_else(|| SekuraError::Config(format!("Unknown technique layer: {}", layer)))?;

        let max_level = intensity.max_level();
        let techniques: Vec<&TechniqueDefinition> = layer_def.techniques.iter()
            .filter(|t| t.intensity_level() <= max_level)
            .collect();

        Ok(techniques)
    }

    pub fn get_all_techniques_for_layer(
        &self,
        layer: &str,
    ) -> Option<&Vec<TechniqueDefinition>> {
        self.layers.get(layer).map(|l| &l.techniques)
    }

    pub fn available_layers(&self) -> Vec<&str> {
        self.layers.keys().map(|s| s.as_str()).collect()
    }

    pub fn total_techniques(&self) -> usize {
        self.layers.values().map(|l| l.techniques.len()).sum()
    }
}
