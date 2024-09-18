# weep-v0.0.1

A simple and secure command-line password manager written in Rust. It allows users to store, encrypt, and retrieve passwords for different services using an SQLite database.

## Features

- __AES-256-GCM Encryption:__ Passwords are securely encrypted using the ring crate for AES-256 encryption.
- __SQLite Storage:__ Passwords are stored in an SQLite database for persistence.
- __Master Key Protection:__ A master key is required to encrypt and decrypt the passwords.
- __Command-line Interface:__ Simple commands to add, retrieve, and list passwords.

## Getting Started

### Prerequisites

Before building the project, make sure you have the following dependencies installed:

1. **Rust**: Install Rust by following the instructions at [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install).
2. **SQLite Development Libraries**:
    - For Ubuntu/Debian:
      ```bash
      sudo apt-get install libsqlite3-dev
      ```
    - For Fedora:
      ```bash
      sudo dnf install sqlite-devel
      ```
    - For Arch Linux:
      ```bash
      sudo pacman -S sqlite
      ```

### Installing

1. **Clone the repository**:
   ```bash
   git clone https://github.com/williammuchui/weep-v0.0.1.git
   cd weep
   ```

2. **Build the project**:
   ```bash
   cargo build
   ```

3. **Run the project**:
   ```bash
   cargo run
   ```

## Usage

### Add a Password

```bash
$ cargo run
Enter your master key: ********
Choose an option:
1. Add a new password
2. Retrieve a password
3. List all services
4. Exit
1
Enter service name: Github
Enter username: your_username
Enter password: ********
Password stored successfully!
```

### Retrieve a Password

```bash
$ cargo run
Enter your master key: ********
Choose an option:
1. Add a new password
2. Retrieve a password
3. List all services
4. Exit
2
Enter service name: Github
Service: Github
Username: your_username
Password: ********
```

### List All Services

```bash
$ cargo run
Enter your master key: ********
Choose an option:
1. Add a new password
2. Retrieve a password
3. List all services
4. Exit
3
Stored services:
- Github
```

## Project Structure

- `main.rs`: The main entry point of the application. Contains functions for adding, retrieving, and listing passwords.
- `Cargo.toml`: The manifest file containing project dependencies.
- `password_manager.db`: The SQLite database file that stores encrypted password data.

## Security Considerations

- **Master Key**: The master key is used to encrypt and decrypt your passwords. Make sure to use a strong and secure master key.
- **Encryption**: Passwords are encrypted using AES-256-GCM, ensuring data security.
- **Database**: Passwords are stored in an SQLite database. Ensure that this file is securely stored and access is restricted.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

## License

This project is licensed under the GPL License. See the [LICENSE](LICENSE) file for details.

