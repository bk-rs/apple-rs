/*
cargo run -p apple-siwa-client-secret-cli --bin apple_siwa_client_secret_gen -- 'key_id' '/path/AuthKey_xxx.p8' 'team_id' 'client_id'
*/

use std::{env, error, fs};

use apple_siwa_client_secret::create;

fn main() -> Result<(), Box<dyn error::Error>> {
    let key_id = env::args().nth(1).unwrap();
    let auth_key_path = env::args().nth(2).unwrap();
    let team_id = env::args().nth(3).unwrap();
    let client_id = env::args().nth(4).unwrap();

    let auth_key_bytes = fs::read(auth_key_path)?;

    let client_secret = create(key_id, auth_key_bytes, team_id, client_id, None, None)?;

    println!("{}", client_secret);

    Ok(())
}
