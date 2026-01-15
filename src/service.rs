use std::{collections::HashMap, fmt::Display, sync::Mutex};

use actix_web::{
    HttpResponse, Responder, ResponseError, get, post,
    web::{self, Data},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use webauthn_rs::{
    Webauthn,
    prelude::{
        CreationChallengeResponse, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
        RegisterPublicKeyCredential, RequestChallengeResponse, Uuid,
    },
};

use crate::{
    crypto::{Method, PasswordHandler},
    repository::{PasskeyRepository, Repository, UserDTO},
};

#[derive(Debug, Serialize)]
struct ServiceError {
    kind: ErrorKind,
    message: String,
}

impl ServiceError {
    fn internal_server_error() -> HttpResponse {
        HttpResponse::InternalServerError().json(Self {
            kind: ErrorKind::InternalServerError,
            message: format!("An unexpected error occurred"),
        })
    }
}

#[derive(Debug, Serialize)]
enum ErrorKind {
    AlreadyExists,
    AuthenticationFailure,
    DoesNotExist,
    InternalServerError,
}

#[derive(Debug, Deserialize)]
struct SignUpRequest {
    name: String,
    password: String,
    mail: String,
}

#[post("/sign-up")]
async fn sign_up(
    user: web::Json<SignUpRequest>,
    pool: web::ThinData<PgPool>,
    handler: web::Data<PasswordHandler>,
) -> impl Responder {
    let result = Repository::create_user(
        &pool,
        UserDTO::new(&user.mail, &user.name, &user.password, &handler),
    )
    .await;

    match result {
        Ok(_) => HttpResponse::Created().finish(),
        Err(err) => {
            if err.is_unique_violation() {
                HttpResponse::Conflict().json(ServiceError {
                    kind: ErrorKind::AlreadyExists,
                    message: format!("User already exists"),
                })
            } else {
                ServiceError::internal_server_error()
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct SignInRequest {
    mail: String,
    password: String,
}

#[post("/sign-in")]
async fn sign_in(
    user: web::Json<SignInRequest>,
    pool: web::ThinData<PgPool>,
    handler: web::Data<PasswordHandler>,
) -> impl Responder {
    let result = Repository::get_by_mail(&pool, &user.mail).await;

    match result {
        Ok(Some(user_details)) => {
            if handler.is_hash_of(
                &user.password,
                user_details.password_hash(),
                Method::SaltPepper,
            ) {
                HttpResponse::Ok().finish()
            } else {
                HttpResponse::Unauthorized().json(ServiceError {
                    kind: ErrorKind::AuthenticationFailure,
                    message: format!("Failed to authenticate"),
                })
            }
        }
        Ok(None) => HttpResponse::NotFound().json(ServiceError {
            kind: ErrorKind::DoesNotExist,
            message: format!("User does not exist"),
        }),
        Err(_) => ServiceError::internal_server_error(),
    }
}

#[derive(Debug, Deserialize)]
struct Pagination {
    page: Option<i64>,
    page_size: Option<i64>,
}

#[get("/user-credentials")]
async fn user_credentials(
    pagination: web::Query<Pagination>,
    pool: web::ThinData<PgPool>,
) -> impl Responder {
    let result = Repository::get_credentials(
        &pool,
        pagination.page.unwrap_or(0),
        pagination.page_size.unwrap_or(10),
    )
    .await;

    match result {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(_) => ServiceError::internal_server_error(),
    }
}

#[derive(Debug, Deserialize)]
struct StartPasskeyRegistration {
    mail: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct PasskeyCreationChallenge {
    user_id: Uuid,
    creation_challenge_response: CreationChallengeResponse,
}

#[post("/passkey/start-registration")]
async fn start_passkey_registration(
    registration: web::Json<StartPasskeyRegistration>,
    pool: web::ThinData<PgPool>,
    webauthn: web::Data<Webauthn>,
    registration_store: web::Data<Mutex<HashMap<Uuid, PasskeyRegistration>>>,
) -> impl Responder {
    let (user_id, credentials) =
        match PasskeyRepository::get_user_by_mail(&pool, &registration.mail).await {
            Ok(Some(user)) => {
                let credentials =
                    match PasskeyRepository::get_user_credential_ids(&pool, user.id()).await {
                        Ok(credentials) => credentials,
                        Err(_) => return ServiceError::internal_server_error(),
                    };
                (user.id().clone(), Some(credentials))
            }
            Ok(None) => (Uuid::new_v4(), None),
            Err(_) => return ServiceError::internal_server_error(),
        };

    let (creation_challenge_response, passkey_registration) = match webauthn
        .start_passkey_registration(user_id, &registration.mail, &registration.name, credentials)
    {
        Ok(registration_data) => registration_data,
        Err(_) => return ServiceError::internal_server_error(),
    };

    match registration_store.lock() {
        Ok(mut store) => {
            store.insert(user_id, passkey_registration);
            HttpResponse::Ok().json(PasskeyCreationChallenge {
                user_id,
                creation_challenge_response,
            })
        }
        Err(_) => ServiceError::internal_server_error(),
    }
}

#[derive(Debug, Deserialize)]
struct FinishPasskeyRegistration {
    user_id: Uuid,
    register_public_key_credential: RegisterPublicKeyCredential,
}

#[post("/passkey/finish-registration")]
async fn finish_passkey_registration(
    registration: web::Json<FinishPasskeyRegistration>,
    pool: web::ThinData<PgPool>,
    webauthn: web::Data<Webauthn>,
    registration_store: web::Data<Mutex<HashMap<Uuid, PasskeyRegistration>>>,
) -> impl Responder {
    let passkey_registration = match registration_store
        .lock()
        .map(|mut store| store.remove(&registration.user_id))
    {
        Ok(Some(passkey_registration)) => passkey_registration,
        Ok(None) => {
            return HttpResponse::NotFound().json(ServiceError {
                kind: ErrorKind::DoesNotExist,
                message: format!("Passkey registration does not exist"),
            });
        }
        Err(_) => return ServiceError::internal_server_error(),
    };

    let passkey = match webauthn.finish_passkey_registration(
        &registration.register_public_key_credential,
        &passkey_registration,
    ) {
        Ok(passkey) => passkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(ServiceError {
                kind: ErrorKind::AuthenticationFailure,
                message: format!("Failed to authenticate passkey"),
            });
        }
    };

    match PasskeyRepository::create_user_credentials(&pool, &registration.user_id, &passkey).await {
        Ok(_) => HttpResponse::Created().finish(),
        Err(err) => {
            if err.is_unique_violation() {
                HttpResponse::Conflict().json(ServiceError {
                    kind: ErrorKind::AlreadyExists,
                    message: format!("Credential id already exists"),
                })
            } else {
                ServiceError::internal_server_error()
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct StartPasskeyAuthentication {
    mail: String,
}

#[derive(Debug, Serialize)]
struct PasskeyRequestChallenge {
    user_id: Uuid,
    request_challenge_response: RequestChallengeResponse,
}

#[post("/passkey/start-authentication")]
async fn start_passkey_authentication(
    authentication: web::Json<StartPasskeyAuthentication>,
    pool: web::ThinData<PgPool>,
    webauthn: web::Data<Webauthn>,
    authentication_store: web::Data<Mutex<HashMap<Uuid, PasskeyAuthentication>>>,
) -> impl Responder {
    let user_id = match PasskeyRepository::get_user_by_mail(&pool, &authentication.mail).await {
        Ok(Some(user)) => user.id().clone(),
        Ok(None) => {
            return HttpResponse::NotFound().json(ServiceError {
                kind: ErrorKind::DoesNotExist,
                message: format!("User does not exist"),
            });
        }
        Err(_) => return ServiceError::internal_server_error(),
    };

    let passkeys = match PasskeyRepository::get_user_credentials(&pool, &user_id).await {
        Ok(passkeys) => passkeys,
        Err(_) => return ServiceError::internal_server_error(),
    };

    let (request_challenge_response, passkey_authentication) =
        match webauthn.start_passkey_authentication(passkeys.as_slice()) {
            Ok((request_challenge_response, passkey_authentication)) => {
                (request_challenge_response, passkey_authentication)
            }
            Err(_) => return ServiceError::internal_server_error(),
        };

    match authentication_store.lock() {
        Ok(mut store) => {
            store.insert(user_id, passkey_authentication);
            HttpResponse::Ok().json(PasskeyRequestChallenge {
                user_id: user_id,
                request_challenge_response,
            })
        }
        Err(_) => ServiceError::internal_server_error(),
    }
}

#[derive(Debug, Deserialize)]
struct FinishPasskeyAuthentication {
    user_id: Uuid,
    public_key_credential: PublicKeyCredential,
}

#[post("/passkey/finish-authentication")]
async fn finish_passkey_authentication(
    authentication: web::Json<FinishPasskeyAuthentication>,
    webauthn: web::Data<Webauthn>,
    authentication_store: web::Data<Mutex<HashMap<Uuid, PasskeyAuthentication>>>,
) -> impl Responder {
    let passkey_authentication = match authentication_store
        .lock()
        .map(|mut store| store.remove(&authentication.user_id))
    {
        Ok(Some(passkey_authentication)) => passkey_authentication,
        Ok(None) => {
            return HttpResponse::NotFound().json(ServiceError {
                kind: ErrorKind::DoesNotExist,
                message: format!("Passkey authentication does not exist"),
            });
        }
        Err(_) => return ServiceError::internal_server_error(),
    };

    let _result = match webauthn.finish_passkey_authentication(
        &authentication.public_key_credential,
        &passkey_authentication,
    ) {
        Ok(result) => result,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ServiceError {
                kind: ErrorKind::AuthenticationFailure,
                message: format!("Could not authenticate passkey"),
            });
        }
    };

    HttpResponse::Ok().finish()
}
