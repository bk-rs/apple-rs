//! [Doc](https://developer.apple.com/documentation/apple_search_ads/implementing_oauth_for_the_apple_search_ads_api)

use core::time::Duration;

use chrono::{serde::ts_seconds, DateTime, Duration as ChronoDuration, Utc};
use jsonwebtoken::{encode, errors::Error as JsonwebtokenError, Algorithm, EncodingKey, Header};
use openssl::{ec::EcKey, error::ErrorStack as OpensslErrorStack, pkey::PKey};
use serde::{Deserialize, Serialize};

pub const AUDIENCE: &str = "https://appleid.apple.com";
// 180 days
pub const EXPIRATION_TIME_DURATION_SECONDS_MAX: u64 = 86400 * 180;

const EC_PRIVATE_KEY_BEGIN: &[u8] = b"-----BEGIN EC PRIVATE KEY-----";

//
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub iss: Box<str>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    pub aud: Box<str>,
    pub sub: Box<str>,
}

pub fn create(
    key_id: impl AsRef<str>,
    ec_private_key_pem_bytes: impl AsRef<[u8]>,
    team_id: impl AsRef<str>,
    client_id: impl AsRef<str>,
    issued_at: impl Into<Option<DateTime<Utc>>>,
    expiration_time_dur: impl Into<Option<Duration>>,
) -> Result<Box<str>, CreateError> {
    let ec_private_key_pem_bytes = ec_private_key_pem_bytes.as_ref();

    let key = if ec_private_key_pem_bytes
        .windows(EC_PRIVATE_KEY_BEGIN.len())
        .any(|x| x == EC_PRIVATE_KEY_BEGIN)
    {
        let pem_bytes = PKey::from_ec_key(
            EcKey::private_key_from_pem(ec_private_key_pem_bytes)
                .map_err(CreateError::MakeEcKeyFailed)?,
        )
        .map_err(CreateError::MakePKeyFailed)?
        .private_key_to_pem_pkcs8()
        .map_err(CreateError::ToPemPkcs8Failed)?;

        EncodingKey::from_ec_pem(&pem_bytes).map_err(CreateError::MakeEncodingKeyFailed)?
    } else {
        EncodingKey::from_ec_pem(ec_private_key_pem_bytes)
            .map_err(CreateError::MakeEncodingKeyFailed)?
    };

    let mut header = Header::new(Algorithm::ES256);
    header.typ = None;
    header.kid = Some(key_id.as_ref().to_owned());

    let issued_at = issued_at.into().unwrap_or_else(Utc::now);
    let mut expiration_time_dur = expiration_time_dur
        .into()
        .unwrap_or_else(|| Duration::from_secs(EXPIRATION_TIME_DURATION_SECONDS_MAX));
    if expiration_time_dur.as_secs() > EXPIRATION_TIME_DURATION_SECONDS_MAX {
        expiration_time_dur = Duration::from_secs(EXPIRATION_TIME_DURATION_SECONDS_MAX);
    }
    let expiration_time = issued_at + ChronoDuration::seconds(expiration_time_dur.as_secs() as i64);

    let claims = Claims {
        iss: team_id.as_ref().into(),
        iat: issued_at,
        exp: expiration_time,
        aud: AUDIENCE.into(),
        sub: client_id.as_ref().into(),
    };

    let token = encode(&header, &claims, &key).map_err(CreateError::EncodeFailed)?;

    Ok(token.as_str().into())
}

#[derive(Debug)]
pub enum CreateError {
    MakeEcKeyFailed(OpensslErrorStack),
    MakePKeyFailed(OpensslErrorStack),
    ToPemPkcs8Failed(OpensslErrorStack),
    MakeEncodingKeyFailed(JsonwebtokenError),
    EncodeFailed(JsonwebtokenError),
}
impl core::fmt::Display for CreateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CreateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_for_pem() {
        /*
        openssl ecparam -genkey -name prime256v1 -noout -out private-key.pem
        */
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

        println!("{secret}");
        let mut split = secret.split('.');
        assert_eq!(
            split.next().unwrap(),
            "eyJhbGciOiJFUzI1NiIsImtpZCI6ImJhY2FlYmRhLWUyMTktNDFlZS1hOTA3LWUyYzI1YjI0ZDFiMiJ9"
        );
        assert_eq!(split.next().unwrap() , "eyJpc3MiOiJTRUFSQ0hBRFMuMjc0NzhlNzEtM2JiMC00NTg4LTk5OGMtMTgyZTJiNDA1NTc3IiwiaWF0IjoxNjU0NDczNjAwLCJleHAiOjE2NzAwMjU2MDAsImF1ZCI6Imh0dHBzOi8vYXBwbGVpZC5hcHBsZS5jb20iLCJzdWIiOiJTRUFSQ0hBRFMuMjc0NzhlNzEtM2JiMC00NTg4LTk5OGMtMTgyZTJiNDA1NTc3In0");
        split.next();
        assert!(split.next().is_none());
    }

    #[test]
    fn test_create_for_pem_pkcs8() {
        /*
        openssl ecparam -genkey -name prime256v1 -noout -out private-key.pem
        cat private-key.pem | openssl pkcs8 -topk8 -nocrypt -out private-key-pkcs8.pem
        */
        const PEM_PRIVATE_KEY: &str = r#"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgq2fGWVFjydud0FDB
P3B7ikRQu2OlbrTmLC/MuUpwGrihRANCAARjny/vh5AXIu27mu0Kl5Tg2CBVJRBI
5weE3vji3SBYZz/FeQJK6zMtpmuIJCeeqrhXH4ixwsVyuMGP66VnMqVR
-----END PRIVATE KEY-----
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

        println!("{secret}");
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
