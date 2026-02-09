use crate::errors::SekuraError;
use super::Database;

impl Database {
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, SekuraError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(|e| SekuraError::Database(format!("Query failed: {}", e)))?;

        match stmt.query_row(rusqlite::params![key], |row: &rusqlite::Row| row.get::<_, String>(0)) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SekuraError::Database(format!("Query error: {}", e))),
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), SekuraError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        ).map_err(|e| SekuraError::Database(format!("Insert failed: {}", e)))?;
        Ok(())
    }

    pub fn get_all_settings(&self) -> Result<serde_json::Value, SekuraError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT key, value FROM settings")
            .map_err(|e| SekuraError::Database(format!("Query failed: {}", e)))?;

        let mut settings = serde_json::Map::new();
        let rows = stmt.query_map([], |row: &rusqlite::Row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }).map_err(|e| SekuraError::Database(format!("Query error: {}", e)))?;

        for row in rows {
            let (key, value): (String, String) = row.map_err(|e| SekuraError::Database(format!("Row error: {}", e)))?;
            settings.insert(key, serde_json::Value::String(value));
        }

        Ok(serde_json::Value::Object(settings))
    }
}
