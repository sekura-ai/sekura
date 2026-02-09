use tokio::sync::Semaphore;
use std::sync::Arc;

/// Ensures only one git operation runs at a time
pub struct GitSemaphore {
    semaphore: Arc<Semaphore>,
}

impl GitSemaphore {
    pub fn new() -> Self {
        Self { semaphore: Arc::new(Semaphore::new(1)) }
    }

    pub async fn acquire(&self) -> tokio::sync::SemaphorePermit<'_> {
        self.semaphore.acquire().await.expect("Semaphore closed")
    }
}

impl Default for GitSemaphore {
    fn default() -> Self {
        Self::new()
    }
}
