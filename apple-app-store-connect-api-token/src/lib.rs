//! [Doc](https://developer.apple.com/documentation/appstoreconnectapi/generating_tokens_for_api_requests)

use core::time::Duration;

use chrono::{serde::ts_seconds, DateTime, Duration as ChronoDuration, Utc};
use jsonwebtoken::{encode, errors::Error as JsonwebtokenError, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

pub const AUDIENCE: &str = "appstoreconnect-v1";
// six months
pub const EXPIRATION_TIME_DURATION_SECONDS_MAX: u64 = 60 * 60 * 24 * 6;
// 20 minutes
pub const EXPIRATION_TIME_DURATION_SECONDS_MAX_FOR_MOST_REQUESTS: u64 = 60 * 20;

//
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub iss: Box<str>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    pub aud: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<Box<str>>>,
}

pub fn create(
    key_id: impl AsRef<str>,
    auth_key_p8_bytes: impl AsRef<[u8]>,
    issuer_id: impl AsRef<str>,
    scope: impl Into<Option<Vec<Box<str>>>>,
    issued_at: impl Into<Option<DateTime<Utc>>>,
    expiration_time_dur: impl Into<Option<Duration>>,
) -> Result<Box<str>, CreateError> {
    let key = EncodingKey::from_ec_pem(auth_key_p8_bytes.as_ref())
        .map_err(CreateError::MakeEncodingKeyFailed)?;

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JWT".to_owned());
    header.kid = Some(key_id.as_ref().to_owned());

    let issued_at = issued_at.into().unwrap_or_else(Utc::now);
    let mut expiration_time_dur = expiration_time_dur.into().unwrap_or_else(|| {
        Duration::from_secs(EXPIRATION_TIME_DURATION_SECONDS_MAX_FOR_MOST_REQUESTS)
    });
    if expiration_time_dur.as_secs() > EXPIRATION_TIME_DURATION_SECONDS_MAX {
        expiration_time_dur = Duration::from_secs(EXPIRATION_TIME_DURATION_SECONDS_MAX);
    }
    let expiration_time = issued_at + ChronoDuration::seconds(expiration_time_dur.as_secs() as i64);

    let claims = Claims {
        iss: issuer_id.as_ref().into(),
        iat: issued_at,
        exp: expiration_time,
        aud: AUDIENCE.into(),
        scope: scope.into(),
    };

    let token = encode(&header, &claims, &key).map_err(CreateError::EncodeFailed)?;

    Ok(token.as_str().into())
}

#[derive(Debug)]
pub enum CreateError {
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
    fn test_create() {
        /*
        openssl ecparam -genkey -noout -name prime256v1 \
            | openssl pkcs8 -topk8 -nocrypt -out ec-private.pem
        */
        const P8_PRIVATE_KEY: &str = r#"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsXxkulZ+qopu4M9j
++u5MRRIYJQG3oobmJsvhKQx4+uhRANCAARIXRezNaTknAu66ifGy0vCkxTWD7oX
LjUOxL+a+60LCYQsO4O9fzi1klyzxSa3n2ZUvjNkiqlbxufipiYejOZk
-----END PRIVATE KEY-----
        "#;

        const ISSUER_ID: &str = "57246542-96fe-1a63-e053-0824d011072a";
        const KEY_ID: &str = "2X9R4HXF34";

        let secret = create(
            KEY_ID,
            P8_PRIVATE_KEY,
            ISSUER_ID,
            vec!["GET /v1/apps?filter[platform]=IOS".into()],
            "2022-06-06T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
            Duration::from_secs(60 * 60 * 10),
        )
        .unwrap();

        println!("{secret}");
        let mut split = secret.split('.');
        assert_eq!(
            split.next().unwrap(),
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjJYOVI0SFhGMzQifQ"
        );
        assert_eq!(split.next().unwrap() , "eyJpc3MiOiI1NzI0NjU0Mi05NmZlLTFhNjMtZTA1My0wODI0ZDAxMTA3MmEiLCJpYXQiOjE2NTQ0NzM2MDAsImV4cCI6MTY1NDUwOTYwMCwiYXVkIjoiYXBwc3RvcmVjb25uZWN0LXYxIiwic2NvcGUiOlsiR0VUIC92MS9hcHBzP2ZpbHRlcltwbGF0Zm9ybV09SU9TIl19");
        split.next();
        assert!(split.next().is_none());
    }
}
