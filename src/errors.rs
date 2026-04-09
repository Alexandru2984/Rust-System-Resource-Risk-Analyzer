//! Centralised error types for the application.

use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("System monitoring error: {0}")]
    Monitor(String),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialisation error: {0}")]
    Serialisation(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Thread channel error: {0}")]
    Channel(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience type alias.
#[allow(dead_code)]
pub type AppResult<T> = Result<T, AppError>;
