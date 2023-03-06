/*
cargo run -p apple-app-store-connect-api-token-cli --bin apple_app_store_connect_api_token_gen -- 'key_id' '/path/AuthKey_xxx.p8' 'issuer_id'

Or

cargo install apple-app-store-connect-api-token-cli
apple_app_store_connect_api_token_gen 'key_id' '/path/AuthKey_xxx.p8' 'issuer_id'
*/

use std::{env, fs};

use apple_app_store_connect_api_token::create;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_id = env::args().nth(1).unwrap();
    let auth_key_path = env::args().nth(2).unwrap();
    let issuer_id = env::args().nth(3).unwrap();

    let auth_key_bytes = fs::read(auth_key_path)?;

    let token = create(key_id, auth_key_bytes, issuer_id, None, None, None)?;

    println!("{token}");

    Ok(())
}
