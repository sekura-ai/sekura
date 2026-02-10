use chrono::Utc;
use crate::errors::SekuraError;
use super::Database;

impl Database {
    pub fn create_scan(
        &self,
        id: &str,
        target: &str,
        repo_path: Option<&str>,
        intensity: &str,
        provider: &str,
        model: Option<&str>,
        config_path: Option<&str>,
        webhook_url: Option<&str>,
    ) -> Result<(), SekuraError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO scans (id, target, repo_path, intensity, provider, model, status, config_path, webhook_url, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', ?7, ?8, ?9)",
            rusqlite::params![id, target, repo_path, intensity, provider, model, config_path, webhook_url, Utc::now().to_rfc3339()],
        ).map_err(|e| SekuraError::Database(format!("Failed to create scan: {}", e)))?;
        Ok(())
    }

    pub fn update_scan_status(&self, id: &str, status: &str) -> Result<(), SekuraError> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        match status {
            "running" => {
                conn.execute(
                    "UPDATE scans SET status = ?2, started_at = ?3 WHERE id = ?1",
                    rusqlite::params![id, status, now],
                ).map_err(|e| SekuraError::Database(format!("Update failed: {}", e)))?;
            }
            "completed" | "failed" => {
                conn.execute(
                    "UPDATE scans SET status = ?2, completed_at = ?3 WHERE id = ?1",
                    rusqlite::params![id, status, now],
                ).map_err(|e| SekuraError::Database(format!("Update failed: {}", e)))?;
            }
            _ => {
                conn.execute(
                    "UPDATE scans SET status = ?2 WHERE id = ?1",
                    rusqlite::params![id, status],
                ).map_err(|e| SekuraError::Database(format!("Update failed: {}", e)))?;
            }
        }
        Ok(())
    }

    pub fn get_scan(&self, id: &str) -> Result<Option<serde_json::Value>, SekuraError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, target, repo_path, intensity, provider, model, status, current_phase, completed_agents, finding_count_critical, finding_count_high, finding_count_medium, finding_count_low, finding_count_info, total_cost_usd, total_duration_ms, error_message, created_at, started_at, completed_at FROM scans WHERE id = ?1"
        ).map_err(|e| SekuraError::Database(format!("Query failed: {}", e)))?;

        let result = stmt.query_row(rusqlite::params![id], |row: &rusqlite::Row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "target": row.get::<_, String>(1)?,
                "repo_path": row.get::<_, Option<String>>(2)?,
                "intensity": row.get::<_, String>(3)?,
                "provider": row.get::<_, String>(4)?,
                "model": row.get::<_, Option<String>>(5)?,
                "status": row.get::<_, String>(6)?,
                "current_phase": row.get::<_, Option<String>>(7)?,
                "completed_agents": row.get::<_, Option<String>>(8)?,
                "finding_counts": {
                    "critical": row.get::<_, i64>(9)?,
                    "high": row.get::<_, i64>(10)?,
                    "medium": row.get::<_, i64>(11)?,
                    "low": row.get::<_, i64>(12)?,
                    "info": row.get::<_, i64>(13)?,
                },
                "total_cost_usd": row.get::<_, f64>(14)?,
                "total_duration_ms": row.get::<_, i64>(15)?,
                "error": row.get::<_, Option<String>>(16)?,
                "created_at": row.get::<_, String>(17)?,
                "started_at": row.get::<_, Option<String>>(18)?,
                "completed_at": row.get::<_, Option<String>>(19)?,
            }))
        });

        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SekuraError::Database(format!("Query error: {}", e))),
        }
    }

    pub fn list_scans(&self, limit: usize, offset: usize) -> Result<Vec<serde_json::Value>, SekuraError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, target, status, intensity, created_at, completed_at FROM scans ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        ).map_err(|e| SekuraError::Database(format!("Query failed: {}", e)))?;

        let rows = stmt.query_map(rusqlite::params![limit as i64, offset as i64], |row: &rusqlite::Row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "target": row.get::<_, String>(1)?,
                "status": row.get::<_, String>(2)?,
                "intensity": row.get::<_, String>(3)?,
                "created_at": row.get::<_, String>(4)?,
                "completed_at": row.get::<_, Option<String>>(5)?,
            }))
        }).map_err(|e| SekuraError::Database(format!("Query error: {}", e)))?;

        let mut results: Vec<serde_json::Value> = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| SekuraError::Database(format!("Row error: {}", e)))?);
        }
        Ok(results)
    }

    pub fn delete_scan(&self, id: &str) -> Result<bool, SekuraError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute("DELETE FROM scans WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| SekuraError::Database(format!("Delete failed: {}", e)))?;
        Ok(affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_create_and_get_scan() {
        let db = Database::in_memory().unwrap();
        db.create_scan("scan-1", "http://example.com", None, "standard", "anthropic", Some("claude-3"), None, None).unwrap();

        let scan = db.get_scan("scan-1").unwrap().unwrap();
        assert_eq!(scan["id"], "scan-1");
        assert_eq!(scan["target"], "http://example.com");
        assert_eq!(scan["status"], "queued");
        assert_eq!(scan["intensity"], "standard");
        assert_eq!(scan["model"], "claude-3");
    }

    #[test]
    fn test_db_get_nonexistent_scan() {
        let db = Database::in_memory().unwrap();
        let result = db.get_scan("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_db_list_scans_pagination() {
        let db = Database::in_memory().unwrap();
        for i in 0..5 {
            db.create_scan(&format!("scan-{}", i), "http://example.com", None, "standard", "anthropic", None, None, None).unwrap();
        }

        let all = db.list_scans(10, 0).unwrap();
        assert_eq!(all.len(), 5);

        let page = db.list_scans(2, 0).unwrap();
        assert_eq!(page.len(), 2);

        let page2 = db.list_scans(2, 2).unwrap();
        assert_eq!(page2.len(), 2);

        let page3 = db.list_scans(10, 4).unwrap();
        assert_eq!(page3.len(), 1);
    }

    #[test]
    fn test_db_delete_scan() {
        let db = Database::in_memory().unwrap();
        db.create_scan("scan-del", "http://example.com", None, "standard", "anthropic", None, None, None).unwrap();
        assert!(db.get_scan("scan-del").unwrap().is_some());

        let deleted = db.delete_scan("scan-del").unwrap();
        assert!(deleted);
        assert!(db.get_scan("scan-del").unwrap().is_none());
    }

    #[test]
    fn test_db_delete_nonexistent() {
        let db = Database::in_memory().unwrap();
        let deleted = db.delete_scan("no-such-scan").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_db_update_scan_status_running() {
        let db = Database::in_memory().unwrap();
        db.create_scan("scan-run", "http://example.com", None, "standard", "anthropic", None, None, None).unwrap();

        db.update_scan_status("scan-run", "running").unwrap();
        let scan = db.get_scan("scan-run").unwrap().unwrap();
        assert_eq!(scan["status"], "running");
        assert!(scan["started_at"].is_string());
    }

    #[test]
    fn test_db_update_scan_status_completed() {
        let db = Database::in_memory().unwrap();
        db.create_scan("scan-comp", "http://example.com", None, "standard", "anthropic", None, None, None).unwrap();

        db.update_scan_status("scan-comp", "completed").unwrap();
        let scan = db.get_scan("scan-comp").unwrap().unwrap();
        assert_eq!(scan["status"], "completed");
        assert!(scan["completed_at"].is_string());
    }

    #[test]
    fn test_db_update_scan_status_failed() {
        let db = Database::in_memory().unwrap();
        db.create_scan("scan-fail", "http://example.com", None, "standard", "anthropic", None, None, None).unwrap();

        db.update_scan_status("scan-fail", "failed").unwrap();
        let scan = db.get_scan("scan-fail").unwrap().unwrap();
        assert_eq!(scan["status"], "failed");
    }

    #[test]
    fn test_db_create_scan_with_repo() {
        let db = Database::in_memory().unwrap();
        db.create_scan("scan-repo", "http://example.com", Some("/tmp/repo"), "thorough", "openai", None, None, None).unwrap();

        let scan = db.get_scan("scan-repo").unwrap().unwrap();
        assert_eq!(scan["repo_path"], "/tmp/repo");
        assert_eq!(scan["intensity"], "thorough");
    }
}
