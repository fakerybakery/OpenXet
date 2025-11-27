use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Repository not found: {0}")]
    RepoNotFound(String),

    #[error("Repository already exists: {0}")]
    RepoAlreadyExists(String),

    #[error("Invalid reference: {0}")]
    InvalidRef(String),

    #[error("Object not found: {0}")]
    ObjectNotFound(String),

    #[error("Git protocol error: {0}")]
    GitProtocol(String),

    #[error("Authentication required")]
    AuthRequired,

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ServerError::RepoNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            ServerError::RepoAlreadyExists(_) => (StatusCode::CONFLICT, self.to_string()),
            ServerError::InvalidRef(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ServerError::ObjectNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            ServerError::GitProtocol(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ServerError::AuthRequired => (StatusCode::UNAUTHORIZED, self.to_string()),
            ServerError::AuthFailed => (StatusCode::FORBIDDEN, self.to_string()),
            ServerError::PermissionDenied => (StatusCode::FORBIDDEN, self.to_string()),
            ServerError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ServerError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
            ServerError::Io(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        (status, message).into_response()
    }
}

pub type Result<T> = std::result::Result<T, ServerError>;
