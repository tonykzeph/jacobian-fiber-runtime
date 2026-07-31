use std::{net::SocketAddr, str::FromStr, time::Duration};

use clap::{Parser, ValueEnum};
use secrecy::{ExposeSecret, SecretString};

use crate::{JfrError, Result};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, Parser)]
#[command(version, about)]
pub struct ConfigArgs {
    #[arg(long, env = "JFR_BIND", default_value = "0.0.0.0:8080")]
    pub bind: String,

    #[arg(long, env = "JFR_DATABASE_URL")]
    pub database_url: String,

    #[arg(long, env = "JFR_API_KEY_PEPPER")]
    pub api_key_pepper: String,

    #[arg(long, env = "JFR_BOOTSTRAP_API_KEY")]
    pub bootstrap_api_key: String,

    #[arg(long, env = "JFR_BOOTSTRAP_TENANT", default_value = "JFR")]
    pub bootstrap_tenant: String,

    #[arg(long, env = "JFR_BOOTSTRAP_KEY_NAME", default_value = "bootstrap")]
    pub bootstrap_key_name: String,

    #[arg(long, env = "JFR_LOG_FORMAT", value_enum, default_value = "json")]
    pub log_format: LogFormat,

    #[arg(long, env = "JFR_REQUEST_TIMEOUT_SECONDS", default_value_t = 20)]
    pub request_timeout_seconds: u64,

    #[arg(long, env = "JFR_MAX_REQUEST_BYTES", default_value_t = 1_048_576)]
    pub max_request_bytes: usize,

    #[arg(long, env = "JFR_DATABASE_MAX_CONNECTIONS", default_value_t = 20)]
    pub database_max_connections: u32,

    #[arg(long, env = "JFR_DATABASE_MIN_CONNECTIONS", default_value_t = 2)]
    pub database_min_connections: u32,

    #[arg(long, env = "JFR_DATABASE_ACQUIRE_SECONDS", default_value_t = 5)]
    pub database_acquire_seconds: u64,

    #[arg(long, env = "JFR_ALLOWED_ORIGIN")]
    pub allowed_origin: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: SecretString,
    pub api_key_pepper: SecretString,
    pub bootstrap_api_key: SecretString,
    pub bootstrap_tenant: String,
    pub bootstrap_key_name: String,
    pub log_format: LogFormat,
    pub request_timeout: Duration,
    pub max_request_bytes: usize,
    pub database_max_connections: u32,
    pub database_min_connections: u32,
    pub database_acquire_timeout: Duration,
    pub allowed_origin: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let args = ConfigArgs::parse();
        let bind = SocketAddr::from_str(&args.bind)
            .map_err(|error| JfrError::Configuration(format!("invalid JFR_BIND: {error}")))?;
        let config = Self {
            bind,
            database_url: SecretString::from(args.database_url),
            api_key_pepper: SecretString::from(args.api_key_pepper),
            bootstrap_api_key: SecretString::from(args.bootstrap_api_key),
            bootstrap_tenant: args.bootstrap_tenant,
            bootstrap_key_name: args.bootstrap_key_name,
            log_format: args.log_format,
            request_timeout: Duration::from_secs(args.request_timeout_seconds),
            max_request_bytes: args.max_request_bytes,
            database_max_connections: args.database_max_connections,
            database_min_connections: args.database_min_connections,
            database_acquire_timeout: Duration::from_secs(args.database_acquire_seconds),
            allowed_origin: args.allowed_origin,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.api_key_pepper.expose_secret().len() < 32 {
            return Err(JfrError::Configuration(
                "JFR_API_KEY_PEPPER must contain at least 32 characters".to_owned(),
            ));
        }
        if self.bootstrap_api_key.expose_secret().len() < 32 {
            return Err(JfrError::Configuration(
                "JFR_BOOTSTRAP_API_KEY must contain at least 32 characters".to_owned(),
            ));
        }
        if self.bootstrap_tenant.trim().is_empty() {
            return Err(JfrError::Configuration(
                "JFR_BOOTSTRAP_TENANT cannot be empty".to_owned(),
            ));
        }
        if self.database_min_connections > self.database_max_connections {
            return Err(JfrError::Configuration(
                "database minimum connections cannot exceed the maximum".to_owned(),
            ));
        }
        if self.max_request_bytes < 1024 {
            return Err(JfrError::Configuration(
                "JFR_MAX_REQUEST_BYTES must be at least 1024".to_owned(),
            ));
        }
        Ok(())
    }
}
