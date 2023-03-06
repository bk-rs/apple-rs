use core::{future::Future, pin::Pin, time::Duration};
use std::{sync::Arc, time::SystemTime};

use apple_search_ads_client_secret::{
    create as client_secret_create, CreateError as ClientSecretCreateError,
};
use arc_swap::ArcSwap;
use async_sleep::{sleep, timeout, Sleepble};
use http_api_isahc_client::IsahcClient;
use oauth2_apple::AppleProviderForSearchAdsApi;
use oauth2_client::client_credentials_grant::{Flow, FlowExecuteError};
use once_cell::sync::Lazy;

use crate::{IssuedAt, ResponseSuccessfulBody};

//
const CLIENT_SECRET_EXP_DUR: Duration = Duration::from_secs(60 * 60 * 24 * 7);

//
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Manager;

impl Manager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, body: ResponseSuccessfulBody, issued_at: SystemTime) {
        let storage = AccessTokenStorage(Some((body, issued_at)));
        ACCESS_TOKEN_STORAGE.store(Arc::new(storage));
    }

    pub fn clear(&self) {
        let storage = AccessTokenStorage(None);
        ACCESS_TOKEN_STORAGE.store(Arc::new(storage));
    }

    pub fn get_value(&self) -> Option<Box<str>> {
        ACCESS_TOKEN_STORAGE
            .load()
            .0
            .as_ref()
            .map(|(body, _)| body.access_token.as_str().into())
    }

    pub async fn request(
        &self,
        key_id: impl AsRef<str>,
        ec_private_key_pem_bytes: impl AsRef<[u8]>,
        team_id: impl AsRef<str>,
        client_id: impl AsRef<str>,
    ) -> Result<(ResponseSuccessfulBody, IssuedAt), ManagerRequestError> {
        let client_secret = match get_not_expired_client_secret() {
            Some(x) => x,
            None => {
                let issued_at = SystemTime::now();
                let client_secret = client_secret_create(
                    key_id,
                    ec_private_key_pem_bytes,
                    team_id,
                    client_id.as_ref(),
                    None,
                    CLIENT_SECRET_EXP_DUR,
                )
                .map_err(ManagerRequestError::ClientSecretCreateFailed)?;

                let storage = ClientSecretStorage(Some((client_secret.to_owned(), issued_at)));
                CLIENT_SECRET_STORAGE.store(Arc::new(storage));

                client_secret
            }
        };

        let flow = Flow::new(ACCESS_TOKEN_REQUEST_HTTP_CLIENT.to_owned());
        let provider = AppleProviderForSearchAdsApi::new(
            client_id.as_ref().to_string(),
            client_secret.as_ref().to_string(),
        )
        .map_err(|err| ManagerRequestError::OauthProviderMakeFailed(err.to_string().into()))?;

        let issued_at = SystemTime::now();
        let body = flow
            .execute(&provider, None)
            .await
            .map_err(ManagerRequestError::AccessTokenRequestFailed)?;

        let storage = AccessTokenStorage(Some((body.to_owned(), issued_at)));
        ACCESS_TOKEN_STORAGE.store(Arc::new(storage));

        Ok((body, issued_at))
    }

    pub async fn run<SLEEP, RequestCb>(
        &self,
        key_id: &str,
        ec_private_key_pem_bytes: &[u8],
        team_id: &str,
        client_id: &str,
        request_callback: RequestCb,
    ) where
        SLEEP: Sleepble,
        RequestCb: Fn(
                Result<(ResponseSuccessfulBody, IssuedAt), ManagerRequestError>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>
            + Send
            + Sync,
    {
        loop {
            if get_not_expired_access_token().is_some() {
                sleep::<SLEEP>(Duration::from_secs(60 * 3)).await;
                continue;
            }

            match self
                .request(
                    key_id,
                    ec_private_key_pem_bytes.as_ref(),
                    team_id,
                    client_id,
                )
                .await
            {
                Ok((body, issued_at)) => {
                    let _ = timeout::<SLEEP, _>(
                        Duration::from_secs(6),
                        request_callback(Ok((body, issued_at))),
                    )
                    .await;

                    sleep::<SLEEP>(Duration::from_secs(60 * 3)).await;
                    continue;
                }
                Err(err) => {
                    let _ = timeout::<SLEEP, _>(Duration::from_secs(3), request_callback(Err(err)))
                        .await;

                    sleep::<SLEEP>(Duration::from_secs(5)).await;
                    continue;
                }
            }
        }
    }
}

//
#[derive(Debug)]
pub enum ManagerRequestError {
    ClientSecretCreateFailed(ClientSecretCreateError),
    OauthProviderMakeFailed(Box<str>),
    AccessTokenRequestFailed(FlowExecuteError),
}

impl core::fmt::Display for ManagerRequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ManagerRequestError {}

//
//
//
static CLIENT_SECRET_STORAGE: Lazy<ArcSwap<ClientSecretStorage>> =
    Lazy::new(|| ArcSwap::from(Arc::new(ClientSecretStorage::default())));

#[derive(Debug, Clone, Default)]
struct ClientSecretStorage(Option<(Box<str>, IssuedAt)>);

fn get_not_expired_client_secret() -> Option<Box<str>> {
    if let Some((client_secret, issued_at)) = CLIENT_SECRET_STORAGE.load().0.as_ref() {
        if let Ok(dur) = SystemTime::now().duration_since(*issued_at) {
            if dur < (CLIENT_SECRET_EXP_DUR - Duration::from_secs(60 * 10)) {
                return Some(client_secret.to_owned());
            }
        }
    }
    None
}

//
//
//
static ACCESS_TOKEN_STORAGE: Lazy<ArcSwap<AccessTokenStorage>> =
    Lazy::new(|| ArcSwap::from(Arc::new(AccessTokenStorage::default())));

#[derive(Debug, Clone, Default)]
struct AccessTokenStorage(Option<(ResponseSuccessfulBody, IssuedAt)>);

fn get_not_expired_access_token() -> Option<ResponseSuccessfulBody> {
    if let Some((body, issued_at)) = ACCESS_TOKEN_STORAGE.load().0.as_ref() {
        if let Some(body_expires_in) = body.expires_in {
            if let Ok(dur) = SystemTime::now().duration_since(*issued_at) {
                if dur.as_secs() < (body_expires_in as u64 - 60 * 5) {
                    return Some(body.to_owned());
                }
            }
        } else {
            return Some(body.to_owned());
        }
    }
    None
}

//
//
//
static ACCESS_TOKEN_REQUEST_HTTP_CLIENT: Lazy<IsahcClient> =
    Lazy::new(|| IsahcClient::new().expect(""));

#[cfg(test)]
mod example_tokio {
    use super::*;

    use async_sleep::impl_tokio::Sleep;

    //
    #[derive(Debug, Clone)]
    pub struct MyManager {
        inner: Manager,
        ctx: Arc<()>,
    }

    impl MyManager {
        pub async fn new(ctx: Arc<()>) -> Self {
            let inner = Manager::new();

            // TODO, read cache then set
            // inner.set(body, issued_at);

            Self { inner, ctx }
        }

        pub fn get_value(&self) -> Option<Box<str>> {
            self.inner.get_value()
        }

        pub async fn run(
            &self,
            key_id: &str,
            ec_private_key_pem_bytes: &[u8],
            team_id: &str,
            client_id: &str,
        ) {
            self.inner
                .run::<Sleep, _>(
                    key_id,
                    ec_private_key_pem_bytes,
                    team_id,
                    client_id,
                    |ret| {
                        Box::pin({
                            let _ctx = self.ctx.clone();

                            async move {
                                match ret {
                                    Ok((_body, _issued_at)) => {
                                        // TODO, write cache
                                    }
                                    Err(_err) => {
                                        // TODO, log
                                    }
                                }
                            }
                        })
                    },
                )
                .await
        }
    }

    #[tokio::test]
    async fn simple() {
        let ctx = Arc::new(());

        {
            let ctx = ctx.clone();
            let mgr = MyManager::new(ctx).await;

            tokio::spawn(async move {
                mgr.run(
                    "key_id",
                    "ec_private_key_pem_bytes".as_bytes(),
                    "team_id",
                    "client_id",
                )
                .await
            });
        }

        {
            let ctx = ctx.clone();
            let mgr = MyManager::new(ctx).await;

            mgr.get_value();
        }
    }
}
