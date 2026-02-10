use std::path::Path;
use crate::errors::SekuraError;
use tracing::{info, warn};

/// Check if the repository has uncommitted changes.
/// Returns a warning message if there are dirty files, None if clean.
pub fn check_repo_clean(repo_path: &Path) -> Option<String> {
    let repo = match git2::Repository::open(repo_path) {
        Ok(r) => r,
        Err(_) => return None, // Not a git repo, skip check
    };

    let statuses = match repo.statuses(Some(
        git2::StatusOptions::new()
            .include_untracked(true)
            .recurse_untracked_dirs(false),
    )) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let dirty_count = statuses.iter().filter(|s| {
        let status = s.status();
        status.intersects(
            git2::Status::INDEX_NEW
                | git2::Status::INDEX_MODIFIED
                | git2::Status::INDEX_DELETED
                | git2::Status::WT_MODIFIED
                | git2::Status::WT_DELETED
                | git2::Status::WT_NEW,
        )
    }).count();

    if dirty_count > 0 {
        Some(format!(
            "Repository has {} uncommitted change(s). Consider committing before scanning to ensure reproducible results.",
            dirty_count
        ))
    } else {
        None
    }
}

pub async fn create_checkpoint(
    repo_path: &Path,
    agent_name: &str,
    attempt: u32,
) -> Result<(), SekuraError> {
    let repo = git2::Repository::open(repo_path)
        .map_err(|e| SekuraError::Git(format!("Failed to open repo: {}", e)))?;

    let mut index = repo.index()
        .map_err(|e| SekuraError::Git(format!("Failed to get index: {}", e)))?;

    index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .map_err(|e| SekuraError::Git(format!("Failed to add files: {}", e)))?;

    index.write()
        .map_err(|e| SekuraError::Git(format!("Failed to write index: {}", e)))?;

    let tree_oid = index.write_tree()
        .map_err(|e| SekuraError::Git(format!("Failed to write tree: {}", e)))?;

    let tree = repo.find_tree(tree_oid)
        .map_err(|e| SekuraError::Git(format!("Failed to find tree: {}", e)))?;

    let head = repo.head().ok().and_then(|h| h.peel_to_commit().ok());

    let sig = repo.signature()
        .unwrap_or_else(|_| git2::Signature::now("sekura", "sekura@localhost").unwrap());

    let message = format!("[checkpoint] {} attempt {}", agent_name, attempt);

    let parents: Vec<&git2::Commit> = head.iter().collect();
    repo.commit(Some("HEAD"), &sig, &sig, &message, &tree, &parents)
        .map_err(|e| SekuraError::Git(format!("Failed to create checkpoint: {}", e)))?;

    info!(agent = %agent_name, attempt, "Git checkpoint created");
    Ok(())
}

pub async fn commit_success(
    repo_path: &Path,
    agent_name: &str,
) -> Result<(), SekuraError> {
    let repo = git2::Repository::open(repo_path)
        .map_err(|e| SekuraError::Git(format!("Failed to open repo: {}", e)))?;

    let mut index = repo.index()
        .map_err(|e| SekuraError::Git(format!("Failed to get index: {}", e)))?;

    index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .map_err(|e| SekuraError::Git(format!("Failed to add files: {}", e)))?;

    index.write()
        .map_err(|e| SekuraError::Git(format!("Failed to write index: {}", e)))?;

    let tree_oid = index.write_tree()
        .map_err(|e| SekuraError::Git(format!("Failed to write tree: {}", e)))?;

    let tree = repo.find_tree(tree_oid)
        .map_err(|e| SekuraError::Git(format!("Failed to find tree: {}", e)))?;

    let head = repo.head()
        .map_err(|e| SekuraError::Git(format!("No HEAD: {}", e)))?
        .peel_to_commit()
        .map_err(|e| SekuraError::Git(format!("HEAD not a commit: {}", e)))?;

    let sig = repo.signature()
        .unwrap_or_else(|_| git2::Signature::now("sekura", "sekura@localhost").unwrap());

    let message = format!("[success] {} completed", agent_name);
    repo.commit(Some("HEAD"), &sig, &sig, &message, &tree, &[&head])
        .map_err(|e| SekuraError::Git(format!("Failed to commit: {}", e)))?;

    info!(agent = %agent_name, "Git success commit");
    Ok(())
}

pub async fn rollback(
    repo_path: &Path,
    reason: &str,
) -> Result<(), SekuraError> {
    let repo = git2::Repository::open(repo_path)
        .map_err(|e| SekuraError::Git(format!("Failed to open repo: {}", e)))?;

    let head = repo.head()
        .map_err(|e| SekuraError::Git(format!("No HEAD: {}", e)))?
        .peel_to_commit()
        .map_err(|e| SekuraError::Git(format!("HEAD not a commit: {}", e)))?;

    // Check if current commit is a checkpoint
    let message = head.message().unwrap_or("");
    if message.starts_with("[checkpoint]") {
        if let Some(parent) = head.parent(0).ok() {
            repo.reset(parent.as_object(), git2::ResetType::Hard, None)
                .map_err(|e| SekuraError::Git(format!("Failed to rollback: {}", e)))?;
            warn!(reason, "Rolled back to previous checkpoint");
        }
    }

    Ok(())
}
