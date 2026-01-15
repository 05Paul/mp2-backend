use rand::distr::{Alphanumeric, SampleString};
use sha2::{Digest, Sha512};

pub struct PasswordHandler {
    salt_length: usize,
    pepper: String,
}

impl PasswordHandler {
    pub fn new(salt_length: usize, pepper: String) -> Self {
        Self {
            salt_length,
            pepper,
        }
    }

    pub fn hash(&self, value: &str, method: Method) -> String {
        let salt = match method {
            Method::Salt | Method::SaltPepper => {
                let salt = self.generate_string(self.salt_length);
                Some(salt)
            }
            _ => None,
        };

        let pepper = match method {
            Method::Pepper | Method::SaltPepper => Some(self.pepper.as_str()),
            _ => None,
        };

        Self::hash_internal(value, salt.as_deref(), pepper)
    }

    pub fn is_hash_of(&self, value: &str, original_hash: &str, method: Method) -> bool {
        let salt = match method {
            Method::Salt | Method::SaltPepper => Self::extract_salt(original_hash),
            _ => None,
        };

        let pepper = match method {
            Method::Pepper | Method::SaltPepper => Some(self.pepper.as_str()),
            _ => None,
        };

        let hash = Self::hash_internal(value, salt, pepper);

        hash == original_hash
    }

    fn hash_internal(value: &str, salt: Option<&str>, pepper: Option<&str>) -> String {
        let pre_hash = format!("{value}{}{}", pepper.unwrap_or(""), salt.unwrap_or(""));
        let hash = hex::encode(&Sha512::digest(&pre_hash)[..]);

        match salt {
            Some(salt) => format!("{salt}${hash}"),
            None => hash,
        }
    }

    fn extract_salt(value: &str) -> Option<&str> {
        let (salt, _) = value.split_once("$")?;
        Some(salt)
    }

    fn generate_string(&self, length: usize) -> String {
        let mut random = rand::rng();
        Alphanumeric.sample_string(&mut random, length)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Method {
    Hash,
    Salt,
    Pepper,
    SaltPepper,
}
