use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use aws_sdk_dynamodb::error::{PutItemError, QueryError};
use aws_sdk_dynamodb::types::SdkError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Config(config::ConfigError),
    DynamoDb(aws_sdk_dynamodb::Error),
    InvalidUri(http::uri::InvalidUri),
    DbRecordNotFound,
    Bcrypt(bcrypt::BcryptError),
    Paseto,
    TotpError,
    ChronoParse(chrono::format::ParseError),
    QrError(String),
    InvalidHeaderValue(http::header::InvalidHeaderValue),
    DynamoDbQuery(SdkError<QueryError>),
    DynamoDbPutItem(SdkError<PutItemError>),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        tracing::error!("Error: {:?}", self);
        (StatusCode::INTERNAL_SERVER_ERROR, "UNHANDLED_CLIENT_ERROR").into_response()
    }
}

impl From<config::ConfigError> for Error {
    fn from(err: config::ConfigError) -> Self {
        Error::Config(err)
    }
}

impl From<aws_sdk_dynamodb::Error> for Error {
    fn from(err: aws_sdk_dynamodb::Error) -> Self {
        Error::DynamoDb(err)
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(err: http::uri::InvalidUri) -> Self {
        Error::InvalidUri(err)
    }
}

impl From<bcrypt::BcryptError> for Error {
    fn from(err: bcrypt::BcryptError) -> Self {
        Error::Bcrypt(err)
    }
}

impl From<chrono::format::ParseError> for Error {
    fn from(err: chrono::format::ParseError) -> Self {
        Error::ChronoParse(err)
    }
}

use qrcode_generator::QRCodeError;
impl From<QRCodeError> for Error {
    fn from(err: QRCodeError) -> Self {
        Error::QrError(err.to_string())
    }
}

impl From<http::header::InvalidHeaderValue> for Error {
    fn from(err: http::header::InvalidHeaderValue) -> Self {
        Error::InvalidHeaderValue(err)
    }
}

impl From<SdkError<QueryError>> for Error {
    fn from(err: SdkError<QueryError>) -> Self {
        Error::DynamoDbQuery(err)
    }
}

impl From<SdkError<PutItemError>> for Error {
    fn from(err: SdkError<PutItemError>) -> Self {
        Error::DynamoDbPutItem(err)
    }
}
