mod key_envelope;
use std::io::{self, Write};
use key_envelope::{KeyEnvelope};

// 创建 vault，生成密钥信封并保存到本地文件。
// Create a vault, generate its key envelope, and save it locally.
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

// 根据 vault_id 加载已有的 vault。
// Load an existing vault by its vault_id.
fn select_vault() -> Result<(), String> {
    let mut vault_id = String::new();
    print!("vault_id: ");
    io::stdout().flush().unwrap(); 
    io::stdin().read_line(&mut vault_id).expect("Failed to read line");
    let envelope = KeyEnvelope::from_vault_file(&vault_id)?;
    envelope.repr();
    Ok(())
}


// 程序入口：根据用户输入选择创建或加载 vault。
// Program entry point: create or load a vault based on the user's input.
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
    } else if input.trim() == "test" {
        //key_envelope::test();
        key_envelope::test_dec();
    }
    Ok(())
}

pub fn test() -> Result<(), String> {
    let envelope = KeyEnvelope::from_vault_file("test123")?;
    let master_password = "test123";
    let dek = envelope.get_dek(&master_password)?;
    println!("{:?}", dek);
    let nonce = random_bytes::<24>()?;
    let cipher = XChaCha20Poly1305::new_from_slice(&dek)
        .map_err(|_| "DEK 长度错误".to_string())?;
    let xnonce = XNonce::try_from(nonce.as_slice())
        .map_err(|_| "Nonce 长度错误".to_string())?;

    let ciphertext = cipher
        .encrypt(
            &xnonce,
            Payload {
                msg: b"Zellane",
                aad: b"private-vault|field-v1",
            },
        )
        .map_err(|_| "字段加密失败".to_string())?;

    let format_version: u8 = 1;
    let mut result = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());

    result.push(format_version);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    println!("result: {:?}", result);
    Ok(())
}
// [1, 131, 187, 158, 202, 114, 211, 15, 229, 16, 198, 79, 214, 4, 73, 20, 200, 152, 126, 217, 2, 211, 52, 144, 205, 70, 46, 31, 151, 165, 103, 93, 213, 140, 50, 72, 94, 77, 242, 186, 195, 100, 97, 134, 46, 117, 176, 33]
//[1, 81, 164, 199, 74, 34, 181, 55, 10, 65, 49, 207, 194, 0, 191, 250, 140, 51, 50, 158, 128, 212, 11, 112, 19, 22, 1, 4, 241, 235, 48, 229, 218, 179, 21, 89, 41, 93, 46, 27, 153, 232, 25, 246, 223, 72, 165, 50]

pub fn test_dec() -> Result<(), String> {
    let encrypted = [1, 131, 187, 158, 202, 114, 211, 15, 229, 16, 198, 79, 214, 4, 73, 20, 200, 152, 126, 217, 2, 211, 52, 144, 205, 70, 46, 31, 151, 165, 103, 93, 213, 140, 50, 72, 94, 77, 242, 186, 195, 100, 97, 134, 46, 117, 176, 33];
    if encrypted.len() < 1 + NONCE_LEN + 16 {
        return Err("加密字段长度不足".to_string());
    }

    let format_version = encrypted[0];
    if format_version != 1 {
        return Err(format!(
            "不支持的字段格式版本: {}",
            format_version
        ));
    }
    let envelope = KeyEnvelope::from_vault_file("test123")?;
    let master_password = "test123";
    let dek = envelope.get_dek(&master_password)?;
    let nonce_start = 1;
    let nonce_end = nonce_start + NONCE_LEN;

    let nonce = &encrypted[nonce_start..nonce_end];
    let ciphertext = &encrypted[nonce_end..];

    let xnonce = XNonce::try_from(nonce)
        .map_err(|_| "Nonce 长度错误".to_string())?;

    let cipher = XChaCha20Poly1305::new_from_slice(&dek)
        .map_err(|_| "DEK 长度错误".to_string())?;

    let result = cipher
        .decrypt(
            &xnonce,
            Payload {
                msg: ciphertext,
                aad: b"private-vault|field-v1",
            },
        )
        .map_err(|_| "字段解密失败或数据已被篡改".to_string())?;
    println!("result: {:?}", String::from_utf8(result).unwrap());
    Ok(())
}