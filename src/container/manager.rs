use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, StartContainerOptions, StopContainerOptions,
    RemoveContainerOptions, ListContainersOptions,
};
use bollard::models::HostConfig;
use std::collections::HashMap;
use crate::config::ContainerConfig;
use crate::errors::SekuraError;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq)]
pub enum ContainerStatus {
    Running,
    Stopped,
    NotFound,
}

pub struct ContainerManager {
    docker: Docker,
    image: String,
    container_name: String,
    network_mode: String,
    capabilities: Vec<String>,
}

impl ContainerManager {
    pub async fn new(config: &ContainerConfig) -> Result<Self, SekuraError> {
        let docker = Docker::connect_with_local_defaults()
            .map_err(|e| SekuraError::Container(format!("Failed to connect to Docker: {}", e)))?;

        Ok(Self {
            docker,
            image: config.image.clone().unwrap_or_else(|| "sekura-kali:latest".to_string()),
            container_name: config.name.clone().unwrap_or_else(|| "sekura-kali".to_string()),
            network_mode: config.network_mode.clone().unwrap_or_else(|| "host".to_string()),
            capabilities: config.capabilities.clone().unwrap_or_else(|| vec!["NET_RAW".into(), "NET_ADMIN".into()]),
        })
    }

    pub async fn status(&self) -> ContainerStatus {
        let mut filters = HashMap::new();
        filters.insert("name".to_string(), vec![self.container_name.clone()]);

        let options = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        match self.docker.list_containers(Some(options)).await {
            Ok(containers) => {
                for container in &containers {
                    if let Some(names) = &container.names {
                        let target = format!("/{}", self.container_name);
                        if names.iter().any(|n| n == &target) {
                            return match container.state.as_deref() {
                                Some("running") => ContainerStatus::Running,
                                _ => ContainerStatus::Stopped,
                            };
                        }
                    }
                }
                ContainerStatus::NotFound
            }
            Err(_) => ContainerStatus::NotFound,
        }
    }

    pub async fn ensure_running(&self) -> Result<(), SekuraError> {
        match self.status().await {
            ContainerStatus::Running => {
                info!(container = %self.container_name, "Container already running");
                Ok(())
            }
            ContainerStatus::Stopped => {
                info!(container = %self.container_name, "Starting existing container");
                self.start_existing().await
            }
            ContainerStatus::NotFound => {
                info!(container = %self.container_name, "Creating and starting new container");
                self.ensure_image().await?;
                self.create_and_start().await
            }
        }
    }

    async fn start_existing(&self) -> Result<(), SekuraError> {
        self.docker
            .start_container(&self.container_name, None::<StartContainerOptions<String>>)
            .await
            .map_err(|e| SekuraError::Container(format!("Failed to start container: {}", e)))?;
        Ok(())
    }

    async fn ensure_image(&self) -> Result<(), SekuraError> {
        match self.docker.inspect_image(&self.image).await {
            Ok(_) => {
                info!(image = %self.image, "Image found locally");
                Ok(())
            }
            Err(_) => {
                warn!(image = %self.image, "Image not found locally, attempting to build from Dockerfile.kali");
                Err(SekuraError::Container(format!(
                    "Image '{}' not found. Build with: docker build -t {} -f docker/Dockerfile.kali .",
                    self.image, self.image
                )))
            }
        }
    }

    async fn create_and_start(&self) -> Result<(), SekuraError> {
        let host_config = HostConfig {
            network_mode: Some(self.network_mode.clone()),
            cap_add: Some(self.capabilities.clone()),
            shm_size: Some(2 * 1024 * 1024 * 1024), // 2GB
            ..Default::default()
        };

        let config = Config {
            image: Some(self.image.clone()),
            cmd: Some(vec!["sleep".to_string(), "infinity".to_string()]),
            host_config: Some(host_config),
            ..Default::default()
        };

        let options = CreateContainerOptions {
            name: &self.container_name,
            platform: None,
        };

        self.docker.create_container(Some(options), config).await
            .map_err(|e| SekuraError::Container(format!("Failed to create container: {}", e)))?;

        self.docker
            .start_container(&self.container_name, None::<StartContainerOptions<String>>)
            .await
            .map_err(|e| SekuraError::Container(format!("Failed to start container: {}", e)))?;

        info!(container = %self.container_name, "Container created and started");
        Ok(())
    }

    pub async fn stop(&self, remove: bool) -> Result<(), SekuraError> {
        let status = self.status().await;
        if status == ContainerStatus::NotFound {
            return Ok(());
        }

        if status == ContainerStatus::Running {
            self.docker
                .stop_container(&self.container_name, Some(StopContainerOptions { t: 10 }))
                .await
                .map_err(|e| SekuraError::Container(format!("Failed to stop container: {}", e)))?;
            info!(container = %self.container_name, "Container stopped");
        }

        if remove {
            self.docker
                .remove_container(
                    &self.container_name,
                    Some(RemoveContainerOptions { force: true, ..Default::default() }),
                )
                .await
                .map_err(|e| SekuraError::Container(format!("Failed to remove container: {}", e)))?;
            info!(container = %self.container_name, "Container removed");
        }

        Ok(())
    }

    pub fn docker(&self) -> &Docker {
        &self.docker
    }

    pub fn container_name(&self) -> &str {
        &self.container_name
    }
}
