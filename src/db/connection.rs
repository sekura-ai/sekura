use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};
use crate::errors::SekuraError;

pub struct Database {
    pub(crate) conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, SekuraError> {
        // Ensure parent directory exists
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)
            .map_err(|e| SekuraError::Database(format!("Failed to open database: {}", e)))?;

        // Enable WAL mode for better concurrency
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| SekuraError::Database(format!("Failed to set pragmas: {}", e)))?;

        let db = Self { conn: Arc::new(Mutex::new(conn)) };
        db.initialize()?;
        Ok(db)
    }

    pub fn in_memory() -> Result<Self, SekuraError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| SekuraError::Database(format!("Failed to open in-memory db: {}", e)))?;
        let db = Self { conn: Arc::new(Mutex::new(conn)) };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> Result<(), SekuraError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(super::schema::CREATE_TABLES)
            .map_err(|e| SekuraError::Database(format!("Failed to create tables: {}", e)))?;
        Ok(())
    }

    pub fn conn(&self) -> Arc<Mutex<Connection>> {
        self.conn.clone()
    }
}

impl Clone for Database {
    fn clone(&self) -> Self {
        Self { conn: self.conn.clone() }
    }
}
