use std::net::{IpAddr, SocketAddr};

use config::Config;
use serde::{Deserialize, Serialize};

use crate::error::Error;

pub struct Configuration {
    app: AppConfiguration,
    server: ServerConfiguration,
    postgres: PostgresConfiguration,
}

impl Configuration {
    pub fn try_from_env() -> Result<Self, Error> {
        let app = AppConfiguration::try_from_env()?;
        let server = ServerConfigurationBuilder::try_from_env()?.try_build()?;
        let postgres = PostgresConfiguration::try_from_env()?;

        Ok(Self {
            app,
            server,
            postgres,
        })
    }

    pub fn server_socket(&self) -> SocketAddr {
        self.server.socket
    }

    pub fn database_url(&self) -> String {
        self.postgres.url()
    }

    pub fn app_config(&self) -> &AppConfiguration {
        &self.app
    }
}

struct ServerConfiguration {
    socket: SocketAddr,
}

#[derive(Deserialize, Serialize)]
#[serde(default)]
struct ServerConfigurationBuilder {
    address: String,
    port: u16,
}

impl ServerConfigurationBuilder {
    fn try_from_env() -> Result<Self, Error> {
        Ok(Config::builder()
            .add_source(config::Environment::with_prefix("server"))
            .build()?
            .try_deserialize::<ServerConfigurationBuilder>()?)
    }

    fn try_build(self) -> Result<ServerConfiguration, Error> {
        Ok(ServerConfiguration {
            socket: SocketAddr::new(IpAddr::V4(self.address.parse()?), self.port),
        })
    }
}

impl Default for ServerConfigurationBuilder {
    fn default() -> Self {
        Self {
            address: "127.0.0.1".into(),
            port: 8080,
        }
    }
}

#[derive(Deserialize)]
#[serde(default)]
struct PostgresConfiguration {
    user: String,
    password: String,
    host: String,
    port: u16,
    database: String,
}

impl PostgresConfiguration {
    fn try_from_env() -> Result<Self, Error> {
        Ok(Config::builder()
            .add_source(config::Environment::with_prefix("pg"))
            .build()?
            .try_deserialize::<PostgresConfiguration>()?)
    }

    fn url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, self.database
        )
    }
}

impl Default for PostgresConfiguration {
    fn default() -> Self {
        Self {
            user: "postgres".into(),
            password: "postgres".into(),
            host: "127.0.0.1".into(),
            port: 5432,
            database: "default".into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(default)]
pub struct AppConfiguration {
    pub pepper: String,
    pub rp_id: String,
    pub webauthn_allow_any_port: bool,
    pub webauthn_allow_subdomains: bool,
    rp_origins: String,
}

impl AppConfiguration {
    fn try_from_env() -> Result<Self, Error> {
        Ok(Config::builder()
            .add_source(config::Environment::with_prefix("app"))
            .build()?
            .try_deserialize::<AppConfiguration>()?)
    }

    pub fn rp_origins(&self) -> Vec<&str> {
        self.rp_origins.split(";").collect()
    }
}

impl Default for AppConfiguration {
    fn default() -> Self {
        Self {
            pepper: "Pepper".into(),
            rp_id: "localhost".into(),
            rp_origins: "http://localhost".into(),
            webauthn_allow_any_port: true,
            webauthn_allow_subdomains: false,
        }
    }
}
