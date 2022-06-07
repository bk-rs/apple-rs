//! [Doc](https://developer.apple.com/documentation/apple_search_ads/implementing_oauth_for_the_apple_search_ads_api)

use std::{error, fmt, time::Duration};

use chrono::{serde::ts_seconds, DateTime, Duration as ChronoDuration, Utc};
use jwt::{AlgorithmType, Error as JwtError, Header, PKeyWithDigest, SignWithKey, Token};
use openssl::{ec::EcKey, error::ErrorStack as OpensslErrorStack, hash::MessageDigest, pkey::PKey};
use serde::{Deserialize, Serialize};

pub const AUDIENCE: &str = "https://appleid.apple.com";
// 180 days
pub const EXPIRATION_TIME_DURATION_SECONDS_MAX: u64 = 86400 * 180;

//
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub iss: String,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    pub aud: String,
    pub sub: String,
}

pub fn create(
    key_id: impl AsRef<str>,
    pem_private_key_bytes: impl AsRef<[u8]>,
    team_id: impl AsRef<str>,
    client_id: impl AsRef<str>,
    issued_at: impl Into<Option<DateTime<Utc>>>,
    expiration_time_dur: impl Into<Option<Duration>>,
) -> Result<String, CreateError> {
    let pkey = PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: PKey::from_ec_key(
            EcKey::private_key_from_pem(pem_private_key_bytes.as_ref())
                .map_err(CreateError::MakeEcKeyFailed)?,
        )
        .map_err(CreateError::MakePKeyFailed)?,
    };

    let header = Header {
        algorithm: AlgorithmType::Es256,
        key_id: Some(key_id.as_ref().to_owned()),
        ..Default::default()
    };

    let issued_at = issued_at.into().unwrap_or_else(Utc::now);
    let mut expiration_time_dur = expiration_time_dur
        .into()
        .unwrap_or_else(|| Duration::from_secs(EXPIRATION_TIME_DURATION_SECONDS_MAX));
    if expiration_time_dur.as_secs() > EXPIRATION_TIME_DURATION_SECONDS_MAX {
        expiration_time_dur = Duration::from_secs(EXPIRATION_TIME_DURATION_SECONDS_MAX);
    }
    let expiration_time = issued_at + ChronoDuration::seconds(expiration_time_dur.as_secs() as i64);

    let claims = Claims {
        iss: team_id.as_ref().to_owned(),
        iat: issued_at,
        exp: expiration_time,
        aud: AUDIENCE.to_owned(),
        sub: client_id.as_ref().to_owned(),
    };

    let token = Token::new(header, claims)
        .sign_with_key(&pkey)
        .map_err(CreateError::TokenSignFailed)?;

    Ok(token.as_str().to_owned())
}

#[derive(Debug)]
pub enum CreateError {
    MakeEcKeyFailed(OpensslErrorStack),
    MakePKeyFailed(OpensslErrorStack),
    TokenSignFailed(JwtError),
}
impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl error::Error for CreateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create() {
        const PEM_PRIVATE_KEY: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKtnxllRY8nbndBQwT9we4pEULtjpW605iwvzLlKcBq4oAoGCCqGSM49
AwEHoUQDQgAEY58v74eQFyLtu5rtCpeU4NggVSUQSOcHhN744t0gWGc/xXkCSusz
LaZriCQnnqq4Vx+IscLFcrjBj+ulZzKlUQ==
-----END EC PRIVATE KEY-----
        "#;

        const CLIENT_ID: &str = "SEARCHADS.27478e71-3bb0-4588-998c-182e2b405577";
        const TEAM_ID: &str = "SEARCHADS.27478e71-3bb0-4588-998c-182e2b405577";
        const KEY_ID: &str = "bacaebda-e219-41ee-a907-e2c25b24d1b2";

        let secret = create(
            KEY_ID,
            PEM_PRIVATE_KEY,
            TEAM_ID,
            CLIENT_ID,
            "2022-06-06T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
            Duration::from_secs(3600 * 24 * 180),
        )
        .unwrap();

        /*
        eyJhbGciOiJFUzI1NiIsImtpZCI6ImJhY2FlYmRhLWUyMTktNDFlZS1hOTA3LWUyYzI1YjI0ZDFiMiJ9.eyJpc3MiOiJTRUFSQ0hBRFMuMjc0NzhlNzEtM2JiMC00NTg4LTk5OGMtMTgyZTJiNDA1NTc3IiwiaWF0IjoxNjU0NDczNjAwLCJleHAiOjE2NzAwMjU2MDAsImF1ZCI6Imh0dHBzOi8vYXBwbGVpZC5hcHBsZS5jb20iLCJzdWIiOiJTRUFSQ0hBRFMuMjc0NzhlNzEtM2JiMC00NTg4LTk5OGMtMTgyZTJiNDA1NTc3In0.bN3KRWDJft-rjqRbOuuzfsImPT4RPEy01ILYJRBe4v_WJtJdi-7xBpi9UCcSN1WRe3Ozobvou5ruxXjVFnB_6Q
        */

        println!("{}", secret);
        let mut split = secret.split('.');
        assert_eq!(
            split.next().unwrap(),
            "eyJhbGciOiJFUzI1NiIsImtpZCI6ImJhY2FlYmRhLWUyMTktNDFlZS1hOTA3LWUyYzI1YjI0ZDFiMiJ9"
        );
        assert_eq!(split.next().unwrap() , "eyJpc3MiOiJTRUFSQ0hBRFMuMjc0NzhlNzEtM2JiMC00NTg4LTk5OGMtMTgyZTJiNDA1NTc3IiwiaWF0IjoxNjU0NDczNjAwLCJleHAiOjE2NzAwMjU2MDAsImF1ZCI6Imh0dHBzOi8vYXBwbGVpZC5hcHBsZS5jb20iLCJzdWIiOiJTRUFSQ0hBRFMuMjc0NzhlNzEtM2JiMC00NTg4LTk5OGMtMTgyZTJiNDA1NTc3In0");
        split.next();
        assert!(split.next().is_none());
    }
}
