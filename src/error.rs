use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

pub type Result<T, E = JfrError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum JfrError {
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    VersionConflict(String),
    #[error("{0}")]
    Conflict(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("missing required scope: {0}")]
    Forbidden(String),
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("internal runtime error: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl JfrError {
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::VersionConflict(_) | Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Database(_) | Self::Crypto | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "validation_failed",
            Self::NotFound(_) => "not_found",
            Self::VersionConflict(_) => "version_conflict",
            Self::Conflict(_) => "conflict",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::Database(_) => "database_error",
            Self::Configuration(_) => "configuration_error",
            Self::Crypto => "cryptographic_error",
            Self::Internal(_) => "internal_error",
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::Database(_) => "The persistence layer rejected the operation.".to_owned(),
            Self::Crypto => "The audit certificate could not be produced.".to_owned(),
            Self::Internal(_) => "The runtime could not complete the operation.".to_owned(),
            other => other.to_string(),
        }
    }
}

impl IntoResponse for JfrError {
    fn into_response(self) -> Response {
        if matches!(self, Self::Database(_) | Self::Crypto | Self::Internal(_)) {
            tracing::error!(error = ?self, "request failed");
        }
        (
            self.status(),
            Json(ErrorBody {
                error: ErrorDetail {
                    code: self.code(),
                    message: self.public_message(),
                },
            }),
        )
            .into_response()
    }
}
