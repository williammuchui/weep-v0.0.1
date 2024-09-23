/* Weep version 0.0.1
 * William Muchui
 *williammuchui@gmail.com
 *Sep 18, 2024
 * */
use dotenv::dotenv;
use rpassword::prompt_password;
use std::collections::BTreeMap;
use std::env;
use std::io::{self, Write}; // Added Write for flushing output
use std::process;
use tokio_postgres::{Error, NoTls};
use weep::{
    add_password, change_master_key, change_service_password, create_master_key_table,
    create_table, list_services, retrieve_password, set_new_master_key, validate_user_master_key,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("Database URL must be set");

    let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Error connecting to database: {}", e);
        }
    });

    create_table(&client).await?;
    create_master_key_table(&client).await?;

    let master_key = prompt_password("Enter your master key: ").unwrap();
    if master_key.is_empty() {
        eprintln!("Master Key cannot be empty.");
        return Ok(());
    }

    if !validate_user_master_key(&master_key, &client).await? {
        eprintln!("Invalid Master Key.");
        let change_master_key = prompt("Do you want to set a new Master Key? (y/n): ");
        if change_master_key.to_lowercase().starts_with('y') {
            let new_master_key1 = prompt_password("Enter the new Master Key: ").unwrap();
            let new_master_key2 = prompt_password("Confirm the new Master Key: ").unwrap();
            if new_master_key1 != new_master_key2 {
                eprintln!("Master keys do not match.");
                process::exit(1);
            } else {
                set_new_master_key(&new_master_key1, &client).await?;
            }
        }
    }

    let options = BTreeMap::from([
        ("1", "Add a new password"),
        ("2", "Retrieve a password"),
        ("3", "List all services"),
        ("4", "Change Service Password"),
        ("5", "Change Master Key"),
        ("6", "Set a master Key"),
        ("7", "Exit"),
    ]);

    loop {
        println!("\nChoose an option:");
        for (key, value) in &options {
            println!("{}. {}", key, value);
        }

        let choice = prompt("Your choice: ");
        match choice.as_str() {
            "1" => add_password(&client, &master_key).await?,
            "2" => retrieve_password(&client, &master_key).await?,
            "3" => list_services(&client).await?,
            "4" => change_service_password(),
            "5" => change_master_key(&client).await?,
            "6" => println!("Not implemented yet."),
            "7" => {
                println!("Exiting program...");
                process::exit(0);
            }
            _ => {
                eprintln!("Invalid option. Please try again.");
            }
        }
    }
}

fn prompt(message: &str) -> String {
    print!("{}", message);
    io::stdout().flush().unwrap(); // Ensures the prompt is printed before input
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}
