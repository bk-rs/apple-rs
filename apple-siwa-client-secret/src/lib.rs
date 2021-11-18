//! [Doc](https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens)

use std::{error, fmt, time::Duration};

use chrono::{serde::ts_seconds, DateTime, Duration as ChronoDuration, Utc};
use jwt::{AlgorithmType, Error as JwtError, Header, PKeyWithDigest, SignWithKey, Token};
use openssl::{ec::EcKey, error::ErrorStack as OpensslErrorStack, hash::MessageDigest, pkey::PKey};
use serde::{Deserialize, Serialize};

pub const AUDIENCE: &str = "https://appleid.apple.com";
// 6 months
pub const EXPIRATION_TIME_DURATION_SECONDS_MAX: u64 = 15777000;

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
    p8_auth_key_bytes: &[u8],
    team_id: impl AsRef<str>,
    client_id: impl AsRef<str>,
    issued_at: impl Into<Option<DateTime<Utc>>>,
    expiration_time_dur: impl Into<Option<Duration>>,
) -> Result<String, CreateError> {
    // TOOD, PKey::private_key_from_pkcs8 not working
    let pkey = PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: PKey::from_ec_key(
            EcKey::private_key_from_pem(p8_auth_key_bytes).map_err(CreateError::MakeEcKeyFailed)?,
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
