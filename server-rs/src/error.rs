use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

/// Errors returned by handlers. `Json` carries an exact Node response body;
/// `Internal` mirrors Node's production errorHandler 500 body and logs the cause.
#[derive(Debug)]
pub enum AppError {
    Json(StatusCode, Value),
    Internal(String),
}

impl AppError {
    pub fn json(status: StatusCode, body: Value) -> Self {
        AppError::Json(status, body)
    }

    /// `{error, message}` with Node's operational-error shape.
    pub fn status(status: StatusCode, error: &str, message: &str) -> Self {
        AppError::Json(status, json!({ "error": error, "message": message }))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Json(status, body) => (status, Json(body)).into_response(),
            AppError::Internal(cause) => {
                tracing::error!(%cause, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "Internal server error",
                        "message": "An error occurred while processing your request",
                    })),
                )
                    .into_response()
            }
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;
