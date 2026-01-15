use std::{fmt::Display, io, net};

use sqlx::migrate::MigrateError;
use webauthn_rs::prelude::WebauthnError;

#[derive(Debug)]
pub enum Error {
    ConfigError(config::ConfigError),
    AddrParseError(net::AddrParseError),
    IoError(io::Error),
    SqlxError(sqlx::Error),
    MigrationError(MigrateError),
    WebauthnError(WebauthnError),
    Other(String),
}

impl Error {
    pub fn is_unique_violation(&self) -> bool {
        match self {
            Error::SqlxError(sqlx::Error::Database(err)) => err.is_unique_violation(),
            _ => false,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ConfigError(config_error) => write!(f, "{config_error}"),
            Error::AddrParseError(addr_parse_error) => write!(f, "{addr_parse_error}"),
            Error::IoError(io_error) => write!(f, "{io_error}"),
            Error::SqlxError(sqlx_error) => write!(f, "{sqlx_error}"),
            Error::MigrationError(migrate_error) => write!(f, "{migrate_error}"),
            Error::WebauthnError(webauthn_error) => write!(f, "{webauthn_error}"),
            Error::Other(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<config::ConfigError> for Error {
    fn from(value: config::ConfigError) -> Self {
        Error::ConfigError(value)
    }
}

impl From<net::AddrParseError> for Error {
    fn from(value: net::AddrParseError) -> Self {
        Error::AddrParseError(value)
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Error::IoError(value)
    }
}

impl From<sqlx::Error> for Error {
    fn from(value: sqlx::Error) -> Self {
        Error::SqlxError(value)
    }
}

impl From<MigrateError> for Error {
    fn from(value: MigrateError) -> Self {
        Error::MigrationError(value)
    }
}

impl From<WebauthnError> for Error {
    fn from(value: WebauthnError) -> Self {
        Error::WebauthnError(value)
    }
}
