pub use apple_search_ads_client_secret;
pub use oauth2_apple;
pub use oauth2_client;

//
pub mod single;

pub type ResponseSuccessfulBody =
    oauth2_client::oauth2_core::client_credentials_grant::access_token_response::SuccessfulBody<
        oauth2_apple::AppleScope,
    >;
pub type IssuedAt = std::time::SystemTime;
