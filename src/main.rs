mod key_envelope;
use std::io::{self, Write};
use key_envelope::KeyEnvelope;

fn create_vault()  -> Result<(), String> {
    let mut vault_id = String::new();
    let mut p_pwd = String::new();
    print!("Please enter your vault name: ");
    io::stdout().flush().unwrap(); 
    io::stdin().read_line(&mut vault_id).expect("Failed to read line");
    let file_path = KeyEnvelope::vault_file_path(&vault_id)?;
    if file_path.exists() {
        println!("vault_id already exist");
        return Ok(())
    }
    println!("Your vault_id will be: {vault_id}");
    print!("Enter your primary_password: ");
    io::stdout().flush().unwrap(); 
    io::stdin().read_line(&mut p_pwd).expect("Failed to read line");
    let vault_id = vault_id.trim().to_string();
    let p_pwd = p_pwd.trim().to_string();
    let envelope = KeyEnvelope::new(&p_pwd, vault_id)?;
    let file_path = envelope.save_to_vault_file()?;
    println!("vault id: {}", envelope.vault_id());
    println!("salt length: {}", envelope.kdf().salt().len());
    println!("wrapped DEK length: {}", envelope.key_wrap().ciphertext().len());
    println!("vault file: {}", file_path.display());
    Ok(())
}

fn select_vault() -> Result<(), String> {
    let mut vault_id = String::new();
    print!("vault_id: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut vault_id).expect("Failed to read line");
    let envelope = KeyEnvelope::from_vault_file(&vault_id)?;
    println!("vault id: {}", envelope.vault_id());
    Ok(())
}

fn main() -> std::io::Result<()>{
    print!("create or select: ");
    io::stdout().flush().unwrap(); 
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    if input.trim() == "create" {
        if let Err(error) = create_vault() {
            eprintln!("create vault failed: {error}");
        }
    } else if input.trim() == "select" {
        if let Err(error) = select_vault() {
            eprintln!("select vault failed: {error}");
        }
    }
    Ok(())
}
