mod key_envelope;
use std::io::{self, Write};

fn create_vault()  -> Result<(), String> {
    let mut vault_id = String::new();
    let mut p_pwd = String::new();
    print!("Please enter your vault name: ");
    io::stdout().flush().unwrap(); 
    io::stdin().read_line(&mut vault_id).expect("Failed to read line");
    println!("Your vault_id will be: {vault_id}");
    print!("Enter your primary_password: ");
    io::stdout().flush().unwrap(); 
    io::stdin().read_line(&mut p_pwd).expect("Failed to read line");
    let envelope = key_envelope::KeyEnvelope::new(&p_pwd, vault_id)?;
    println!("vault id: {}", envelope.vault_id());
    println!("salt length: {}", envelope.kdf().salt().len());
    println!("wrapped DEK length: {}", envelope.key_wrap().ciphertext().len());
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
        create_vault();
    }
    Ok(())
}
