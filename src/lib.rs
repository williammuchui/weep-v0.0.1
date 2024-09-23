use base64::{engine::general_purpose::STANDARD, Engine as _};
use bcrypt::{hash, verify, BcryptError, DEFAULT_COST};
use rand::Rng;
use ring::aead;
use rpassword::prompt_password;
use std::io::Write;
use std::process;
use tokio_postgres::{Client, Error};

pub async fn create_master_key_table(client: &Client) -> Result<(), Error> {
    client
        .execute(
            "CREATE TABLE IF NOT EXISTS master_keys (
                id SERIAL PRIMARY KEY,
                key_hash TEXT NOT NULL
            )",
            &[],
        )
        .await?;
    Ok(())
}

pub async fn set_new_master_key(key: &str, client: &Client) -> Result<(), Error> {
    let key_hash = hash_key(key).unwrap();
    client
        .execute(
            "INSERT INTO master_keys (key_hash) VALUES ($1)",
            &[&key_hash],
        )
        .await?;
    println!("Master Key set successfully.");
    Ok(())
}

pub async fn create_table(client: &Client) -> Result<(), Error> {
    client
        .execute(
            "CREATE TABLE IF NOT EXISTS passwords (
                id SERIAL PRIMARY KEY,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password BYTEA NOT NULL
            )",
            &[],
        )
        .await?;
    Ok(())
}

pub fn hash_key(key: &str) -> Result<String, BcryptError> {
    let hashed_key = hash(key, DEFAULT_COST)?;
    Ok(hashed_key)
}

pub async fn add_password(client: &Client, master_key: &str) -> Result<(), Error> {
    let service = prompt("Enter service name: ");
    let username = prompt("Enter username: ");
    let password = prompt_password("Enter password: ").unwrap();

    let encrypted_password = encrypt_password(&master_key, &password).unwrap();

    client
        .execute(
            "INSERT INTO passwords (service, username, password) VALUES ($1, $2, $3)",
            &[&service, &username, &encrypted_password],
        )
        .await?;

    println!("Password stored successfully!");
    Ok(())
}

pub async fn validate_user_master_key(key: &str, client: &Client) -> Result<bool, Error> {
    let rows = client
        .query(
            "SELECT key_hash FROM master_keys WHERE key_hash = $1",
            &[&key],
        )
        .await?;

    if rows.is_empty() {
        return Ok(false);
    }

    let stored_key: String = rows[0].get(0);
    let is_valid = verify(key, &stored_key).unwrap();
    Ok(is_valid)
}

pub async fn retrieve_password(client: &Client, master_key: &str) -> Result<(), Error> {
    let service = prompt("Enter service name: ");
    let rows = client
        .query(
            "SELECT username, password FROM passwords WHERE service = $1",
            &[&service],
        )
        .await?;
    if rows.is_empty() {
        println!("Service not found.");
        return Ok(());
    }

    let username: String = rows[0].get(0);
    let encrypted_password: Vec<u8> = rows[0].get(1);
    let decrypted_password = decrypt_password(&master_key, &encrypted_password).unwrap();

    println!("Service: {}", service);
    println!("Username: {}", username);
    println!("Password: {}", decrypted_password);
    Ok(())
}

pub async fn list_services(client: &Client) -> Result<(), Error> {
    let rows = client.query("SELECT service FROM passwords", &[]).await?;

    println!("Stored services:");
    for row in rows {
        println!("- {}", row.get::<_, String>(0));
    }

    Ok(())
}

pub async fn change_master_key(client: &Client) -> Result<(), Error> {
    let master_key1 = prompt_password("Enter new master key: ").unwrap();
    let master_key2 = prompt_password("Repeat Master Key: ").unwrap();
    if master_key1 != master_key2 {
        eprintln!("Master keys do not match!");
        process::exit(1);
    }
    set_new_master_key(&master_key1, client).await?;
    Ok(())
}

pub fn change_service_password() {
    // Implementation pending
}

fn prompt(message: &str) -> String {
    print!("{}", message);
    std::io::stdout().flush().unwrap(); // Ensure the prompt is printed
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn encrypt_password(
    master_key: &str,
    password: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = derive_key(master_key);
    let mut rng = rand::thread_rng();
    let nonce: [u8; 12] = rng.gen(); // Generate a random nonce

    let mut in_out = password.as_bytes().to_vec();
    in_out.resize(in_out.len() + aead::AES_256_GCM.tag_len(), 0);

    let sealing_key =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());

    sealing_key
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out,
        )
        // .map_err(|e| e.into())?; // Map error to Box<dyn std::error::Error>
        .unwrap();

    let mut combined = nonce.to_vec();
    combined.extend(in_out);
    // Ok(STANDARD.encode(&combined))
    Ok(combined)
}

fn decrypt_password(
    master_key: &str,
    encrypted_password: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let key = derive_key(master_key);
    let decrypted_data = STANDARD.decode(encrypted_password)?;

    let (nonce, ciphertext) = decrypted_data.split_at(12); // Separate nonce and ciphertext
    let nonce = aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()); // Convert to nonce type

    let opening_key =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
    let mut ciphertext = ciphertext.to_vec();

    let decrypted_password = opening_key
        .open_in_place(nonce, aead::Aad::empty(), &mut ciphertext)
        // .map_err(|e| e.into())
        .unwrap();

    Ok(String::from_utf8(decrypted_password.to_vec())?)
}

fn derive_key(master_key: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let master_key_bytes = master_key.as_bytes();
    for (i, byte) in master_key_bytes.iter().enumerate() {
        key[i % 32] ^= byte;
    }
    key
}
