use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use actix_web::{
    App, HttpServer,
    middleware::Logger,
    web::{self, service},
};
use dotenv::dotenv;
use env_logger::{Env, init_from_env};
use sqlx::{PgPool, migrate};
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration, Url, Uuid},
};

use crate::{config::Configuration, crypto::PasswordHandler, error::Error};

mod config;
mod crypto;
mod error;
mod repository;
mod service;

#[actix_web::main]
async fn main() -> Result<(), Error> {
    dotenv().ok();

    init_from_env(Env::new().default_filter_or("info"));

    let config = Configuration::try_from_env()?;

    let (
        password_handler,
        webauthn,
        pool,
        registration_store,
        authentication_store,
        discoverable_store,
    ) = setup(&config).await?;
    let registration_store = web::Data::from(registration_store);
    let authentication_store = web::Data::from(authentication_store);
    let discoverable_store = web::Data::from(discoverable_store);

    migrate!().run(&pool).await?;

    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::ThinData(pool.clone()))
            .app_data(password_handler.clone())
            .app_data(webauthn.clone())
            .app_data(registration_store.clone())
            .app_data(authentication_store.clone())
            .app_data(discoverable_store.clone())
            .wrap(Logger::default())
            .service(service::sign_up)
            .service(service::sign_in)
            .service(service::user_credentials)
            .service(service::start_passkey_registration)
            .service(service::finish_passkey_registration)
            .service(service::start_passkey_authentication)
            .service(service::finish_passkey_authentication)
            .service(service::start_discoverable_authentication)
            .service(service::finish_discoverable_authentication)
    })
    .bind(config.server_socket())?
    .run();

    Ok(server.await?)
}

async fn setup(
    config: &Configuration,
) -> Result<
    (
        web::Data<PasswordHandler>,
        web::Data<Webauthn>,
        PgPool,
        Arc<Mutex<HashMap<Uuid, PasskeyRegistration>>>,
        Arc<Mutex<HashMap<Uuid, PasskeyAuthentication>>>,
        Arc<Mutex<HashMap<Uuid, DiscoverableAuthentication>>>,
    ),
    Error,
> {
    let app_config = config.app_config();
    let password_handler = web::Data::new(PasswordHandler::new(10, app_config.pepper.clone()));

    let rp_id = &app_config.rp_id;
    let rp_origins = app_config.rp_origins();
    let rp_origin = Url::parse(rp_origins.get(0).unwrap_or(&"http://localhost"))
        .map_err(|err| Error::Other(format!("{err}")))?;

    let mut webauthn_builder = WebauthnBuilder::new(rp_id, &rp_origin)?
        .allow_any_port(app_config.webauthn_allow_any_port)
        .allow_subdomains(app_config.webauthn_allow_subdomains);

    for url in rp_origins
        .iter()
        .skip(1)
        .filter_map(|url| Url::parse(url).ok())
    {
        webauthn_builder = webauthn_builder.append_allowed_origin(&url);
    }

    let webauthn = web::Data::new(webauthn_builder.build()?);

    let pool = PgPool::connect(&config.database_url()).await?;

    let registration_store = Arc::new(Mutex::new(HashMap::<Uuid, PasskeyRegistration>::new()));

    let authentication_store = Arc::new(Mutex::new(HashMap::<Uuid, PasskeyAuthentication>::new()));

    let discoverable_store = Arc::new(Mutex::new(
        HashMap::<Uuid, DiscoverableAuthentication>::new(),
    ));

    Ok((
        password_handler,
        webauthn,
        pool,
        registration_store,
        authentication_store,
        discoverable_store,
    ))
}
