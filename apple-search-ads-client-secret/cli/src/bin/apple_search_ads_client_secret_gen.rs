/*
cargo run -p apple-search-ads-client-secret-cli --bin apple_search_ads_client_secret_gen -- 'key_id' '/path/private-key.pem' 'team_id' 'client_id'

Or

cargo install apple-search-ads-client-secret-cli
apple_search_ads_client_secret_gen 'key_id' '/path/private-key.pem' 'team_id' 'client_id'
*/

use std::{env, fs};

use apple_search_ads_client_secret::create;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_id = env::args().nth(1).unwrap();
    let private_key_path = env::args().nth(2).unwrap();
    let team_id = env::args().nth(3).unwrap();
    let client_id = env::args().nth(4).unwrap();

    let private_key_bytes = fs::read(private_key_path)?;

    let client_secret = create(key_id, private_key_bytes, team_id, client_id, None, None)?;

    println!("{client_secret}");

    Ok(())
}
