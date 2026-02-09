use bollard::image::BuildImageOptions;
use futures::StreamExt;
use std::path::Path;
use crate::errors::SekuraError;
use super::manager::ContainerManager;
use tracing::info;

impl ContainerManager {
    /// Build the Kali image from Dockerfile
    pub async fn build_image(&self, dockerfile_path: &Path) -> Result<(), SekuraError> {
        if !dockerfile_path.exists() {
            return Err(SekuraError::Container(format!(
                "Dockerfile not found: {}",
                dockerfile_path.display()
            )));
        }

        let context_dir = dockerfile_path.parent()
            .ok_or_else(|| SekuraError::Container("Invalid Dockerfile path".into()))?;

        info!(
            image = %self.container_name(),
            dockerfile = %dockerfile_path.display(),
            "Building Docker image (this may take a while)..."
        );

        // Create tar archive of the build context
        let mut archive = tar::Builder::new(Vec::new());
        archive.append_dir_all(".", context_dir)
            .map_err(|e| SekuraError::Container(format!("Failed to create build context: {}", e)))?;
        let context = archive.into_inner()
            .map_err(|e| SekuraError::Container(format!("Failed to finalize build context: {}", e)))?;

        let options = BuildImageOptions {
            dockerfile: dockerfile_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Dockerfile.kali"),
            t: self.container_name(),
            rm: true,
            ..Default::default()
        };

        let mut stream = self.docker().build_image(options, None, Some(context.into()));
        while let Some(result) = stream.next().await {
            match result {
                Ok(output) => {
                    if let Some(stream) = output.stream {
                        print!("{}", stream);
                    }
                }
                Err(e) => {
                    return Err(SekuraError::Container(format!("Build failed: {}", e)));
                }
            }
        }

        info!("Image built successfully");
        Ok(())
    }

    /// Copy a file into the running container
    pub async fn copy_file_to(
        &self,
        local_path: &Path,
        container_path: &str,
    ) -> Result<(), SekuraError> {
        let mut archive = tar::Builder::new(Vec::new());

        let file_name = local_path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| SekuraError::Container("Invalid file name".into()))?;

        archive.append_path_with_name(local_path, file_name)
            .map_err(|e| SekuraError::Container(format!("Failed to create archive: {}", e)))?;

        let data = archive.into_inner()
            .map_err(|e| SekuraError::Container(format!("Failed to finalize archive: {}", e)))?;

        self.docker().upload_to_container(
            self.container_name(),
            Some(bollard::container::UploadToContainerOptions {
                path: container_path.to_string(),
                ..Default::default()
            }),
            data.into(),
        ).await
        .map_err(|e| SekuraError::Container(format!("Failed to copy file: {}", e)))?;

        Ok(())
    }
}
