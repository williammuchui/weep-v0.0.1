/* Weep version 0.0.1
 * William Muchui
 *williammuchui@gmail.com
 *Sep 18, 2024
 * */
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::aead;
use rpassword::prompt_password;
use rusqlite::{params, Connection, Result};
use std::collections::BTreeMap;
use std::process;

fn main() -> Result<()> {
    let conn = Connection::open("password_manager.db")?;
    create_table(&conn)?;

    let master_key = prompt_password("Enter your master key: ").unwrap();
    if master_key.is_empty() {
        eprintln!("Master key cannot be empty");
        return Ok(());
    }

    let mut options = BTreeMap::new();
    options.insert("1", "Add a new password");
    options.insert("2", "Retrieve a password");
    options.insert("3", "List all services");
    options.insert("4", "Exit");

    loop {
        println!("Choose an option:");
        for (key, value) in &options {
            println!("{}. {}", key, value);
        }

        let mut choice = String::new();
        std::io::stdin().read_line(&mut choice).unwrap();
        match choice.trim() {
            "1" => add_password(&conn, &master_key)?,
            "2" => retrieve_password(&conn, &master_key)?,
            "3" => list_services(&conn)?,
            "4" => {
                println!("Exiting program...");
                process::exit(0)
            }
            _ => {
                eprintln!("Invalid option.");
            }
        }
    }
}

fn create_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        )",
        [],
    )?;
    Ok(())
}

fn add_password(conn: &Connection, master_key: &str) -> Result<()> {
    let service = prompt("Enter service name: ");
    let username = prompt("Enter username: ");
    let password = prompt_password("Enter password: ").unwrap();

    let encrypted_password = encrypt_password(master_key, &password).unwrap();

    conn.execute(
        "INSERT INTO passwords (service, username, password) VALUES (?1, ?2, ?3)",
        params![service, username, encrypted_password],
    )?;

    println!("Password stored successfully!");
    Ok(())
}

fn retrieve_password(conn: &Connection, master_key: &str) -> Result<()> {
    let service = prompt("Enter service name: ");
    let mut stmt = conn.prepare("SELECT username, password FROM passwords WHERE service = ?1")?;
    let mut rows = stmt.query(params![service])?;

    if let Some(row) = rows.next()? {
        let username: String = row.get(0)?;
        let encrypted_password: String = row.get(1)?;
        let decrypted_password = decrypt_password(master_key, &encrypted_password).unwrap();

        println!("Service: {}", service);
        println!("Username: {}", username);
        println!("Password: {}", decrypted_password);
    } else {
        println!("Service not found.");
    }

    Ok(())
}

fn list_services(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("SELECT service FROM passwords")?;
    let mut rows = stmt.query([])?;

    println!("Stored services:");
    while let Some(row) = rows.next()? {
        let service: String = row.get(0)?;
        println!("- {}", service);
    }

    Ok(())
}

fn prompt(message: &str) -> String {
    let mut input = String::new();
    println!("{}", message);
    std::io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn encrypt_password(
    master_key: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let key = derive_key(master_key);
    let nonce = aead::Nonce::assume_unique_for_key([0u8; 12]); // For simplicity, but should use unique nonce per password
    let mut in_out = password.as_bytes().to_vec();
    // in_out.extend_from_slice(&[0u8; aead::AES_256_GCM.tag_len()]);

    // Extend the buffer to fit the authentication tag
    in_out.resize(in_out.len() + aead::AES_256_GCM.tag_len(), 0);

    let sealing_key =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());

    sealing_key
        .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .unwrap();

    Ok(STANDARD.encode(&in_out))
}

fn decrypt_password(
    master_key: &str,
    encrypted_password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let key = derive_key(master_key);
    let nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
    let mut encrypted_password = STANDARD.decode(encrypted_password)?;

    let opening_key =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
    let decrypted_password = opening_key
        .open_in_place(nonce, aead::Aad::empty(), &mut encrypted_password)
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
