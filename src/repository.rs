use serde::{Deserialize, Serialize};
use serde_json::{Value, to_value};
use sqlx::{
    PgPool, query_file, query_file_as,
    types::{Json, JsonRawValue},
};
use webauthn_rs::prelude::{CredentialID, Passkey, PasskeyRegistration, Uuid};

use crate::{
    crypto::{Method, PasswordHandler},
    error::Error,
};

pub struct Repository;

impl Repository {
    pub async fn get_by_mail(pool: &PgPool, email: &str) -> Result<Option<User>, Error> {
        let record = query_file_as!(User, "queries/get-user-by-mail.sql", email)
            .fetch_one(pool)
            .await;

        match record {
            Ok(user) => Ok(Some(user)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn get_credentials(
        pool: &PgPool,
        page: i64,
        page_size: i64,
    ) -> Result<Vec<User>, Error> {
        let records = query_file_as!(
            User,
            "queries/get-user-credentials.sql",
            page_size,
            page * page_size
        )
        .fetch_all(pool)
        .await;

        Ok(records?)
    }

    pub async fn create_user(pool: &PgPool, user: UserDTO<'_>) -> Result<i64, Error> {
        let record = query_file!(
            "queries/create-user.sql",
            user.name,
            user.email,
            user.password_plain,
            user.password_hashed,
            user.password_salted,
            user.password_peppered,
            user.password_salted_and_peppered
        )
        .fetch_one(pool)
        .await?;

        Ok(record.id)
    }
}

pub struct UserDTO<'a> {
    email: &'a str,
    name: &'a str,
    password_plain: &'a str,
    password_hashed: String,
    password_salted: String,
    password_peppered: String,
    password_salted_and_peppered: String,
}

impl<'a> UserDTO<'a> {
    pub fn new(
        email: &'a str,
        name: &'a str,
        password: &'a str,
        handler: &PasswordHandler,
    ) -> Self {
        Self {
            email,
            name,
            password_plain: password,
            password_hashed: handler.hash(password, Method::Hash),
            password_salted: handler.hash(password, Method::Salt),
            password_peppered: handler.hash(password, Method::Pepper),
            password_salted_and_peppered: handler.hash(password, Method::SaltPepper),
        }
    }
}

#[derive(Serialize)]
pub struct User {
    id: i64,
    email: String,
    name: String,
    password_plain: String,
    password_hashed: String,
    password_salted: String,
    password_peppered: String,
    password_salted_and_peppered: String,
}

impl User {
    pub fn password_hash(&self) -> &str {
        &self.password_salted_and_peppered
    }
}

pub struct PasskeyRepository;

impl PasskeyRepository {
    pub async fn get_user_by_mail(pool: &PgPool, mail: &str) -> Result<Option<PasskeyUser>, Error> {
        let record = query_file_as!(PasskeyUser, "queries/passkey/get-user-by-mail.sql", mail)
            .fetch_one(pool)
            .await;

        match record {
            Ok(user) => Ok(Some(user)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn get_user_by_id(
        pool: &PgPool,
        user_id: &Uuid,
    ) -> Result<Option<PasskeyUser>, Error> {
        let record = query_file_as!(PasskeyUser, "queries/passkey/get-user-by-id.sql", user_id)
            .fetch_one(pool)
            .await;

        match record {
            Ok(user) => Ok(Some(user)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn create_user(pool: &PgPool, user: &PasskeyUser) -> Result<(), Error> {
        let _record = query_file!(
            "queries/passkey/create-user.sql",
            user.id,
            user.mail,
            user.name
        )
        .fetch_one(pool)
        .await?;

        Ok(())
    }

    pub async fn get_user_credential_ids(
        pool: &PgPool,
        user_id: &Uuid,
    ) -> Result<Vec<CredentialID>, Error> {
        let records = query_file_as!(
            CredentialIDWrapper,
            "queries/passkey/get-user-credential-ids-by-user-id.sql",
            user_id
        )
        .fetch_all(pool)
        .await;

        Ok(records?
            .into_iter()
            .map(|wrap| wrap.credential_id)
            .collect())
    }

    pub async fn get_user_credentials(
        pool: &PgPool,
        user_id: &Uuid,
    ) -> Result<Vec<Passkey>, Error> {
        let records = query_file!("queries/passkey/get-user-credentials.sql", user_id)
            .fetch_all(pool)
            .await?;
        Ok(records
            .into_iter()
            .filter_map(|record| {
                let value = record.credential;
                Some(serde_json::from_value::<Passkey>(value).ok()?)
            })
            .collect())
    }

    pub async fn create_user_credentials(
        pool: &PgPool,
        user_id: &Uuid,
        passkey: &Passkey,
    ) -> Result<(), Error> {
        let passkey_json = to_value(passkey).expect("Must be parseable");
        let _record = query_file!(
            "queries/passkey/create-user-credentials.sql",
            passkey.cred_id().as_slice(),
            user_id,
            passkey_json,
        )
        .fetch_one(pool)
        .await?;

        Ok(())
    }
}

#[derive(Serialize)]
pub struct PasskeyUser {
    id: Uuid,
    mail: String,
    name: String,
}

impl PasskeyUser {
    pub fn id(&self) -> &Uuid {
        &self.id
    }
}

struct CredentialIDWrapper {
    credential_id: CredentialID,
}

struct PasskeyWrapper {
    credential: sqlx::types::Json<Passkey>,
}
