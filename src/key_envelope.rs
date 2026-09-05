use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use getrandom::fill;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const KEK_LEN: usize = 32;
const DEK_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyEnvelope  {
    format_version: u16,
    vault_id: String,
    kdf: KdfConfig,
    key_wrap: KeyWrap,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KdfConfig {
    algorithm: String,
    salt: Vec<u8>,
    mem_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyWrap {
    algorithm: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl KeyEnvelope {
    pub fn new(
        master_password: &str,
        vault_id: String,
    ) -> Result<Self, String> {
        let kdf = KdfConfig::new()?;
        let kek = Self::derive_kek_with_kdf(master_password, &kdf)?;
        let dek = random_bytes::<DEK_LEN>()?;
        let key_wrap = KeyWrap::new(&kek, &dek, &vault_id)?;

        let envelope = Self {
            format_version: 1,
            vault_id,
            kdf,
            key_wrap,
        };
        Ok(envelope)
    }

    pub fn derive_kek(&self, master_password: &str) -> Result<[u8; KEK_LEN], String> {
        Self::derive_kek_with_kdf(master_password, &self.kdf)
    }

    fn derive_kek_with_kdf(
        master_password: &str,
        kdf: &KdfConfig,
    ) -> Result<[u8; KEK_LEN], String> {
        if kdf.algorithm != "argon2id" {
            return Err("不支持的 KDF 算法".to_string());
        }

        let params = Params::new(
            kdf.mem_cost_kib,
            kdf.time_cost,
            kdf.parallelism,
            Some(KEK_LEN),
        )
        .map_err(|error| error.to_string())?;

        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        );

        let mut kek = [0u8; KEK_LEN];

        argon2
            .hash_password_into(
                master_password.as_bytes(),
                &kdf.salt,
                &mut kek,
            )
            .map_err(|error| error.to_string())?;

        Ok(kek)
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|error| error.to_string())
    }

    pub fn save_to_vault_file(&self) -> Result<PathBuf, String> {
        let vaults_dir = Self::vaults_dir()?;
        fs::create_dir_all(&vaults_dir)
            .map_err(|error| format!("创建 vaults 目录失败: {error}"))?;

        let file_name = format!("{}.json", self.vault_id().trim());
        let file_path = vaults_dir.join(file_name);
        let json_text = self.to_json()?;
        fs::write(&file_path, json_text)
            .map_err(|error| format!("写入 vault 文件失败: {error}"))?;

        Ok(file_path)
    }

    pub fn from_vault_file(vault_id: &str) -> Result<Self, String> {
        let file_path = Self::vault_file_path(vault_id)?;
        if !file_path.exists() {
            return Err(format!("vault '{}' 不存在: {}", vault_id, file_path.display()));
        }

        let json_text = fs::read_to_string(&file_path)
            .map_err(|error| format!("读取 vault 文件失败: {error}"))?;
        serde_json::from_str(&json_text)
            .map_err(|error| format!("解析 vault JSON 失败: {error}"))
    }

    fn vaults_dir() -> Result<PathBuf, String> {
        let current_dir = std::env::current_dir()
            .map_err(|error| format!("获取当前目录失败: {error}"))?;
        Ok(current_dir.join("vaults"))
    }

    pub fn vault_file_path(vault_id: &str) -> Result<PathBuf, String> {
        let vaults_dir = Self::vaults_dir()?;
        let safe_id = vault_id.trim().replace(['/', '\\'], "_");
        Ok(vaults_dir.join(format!("{safe_id}.json")))
    }

    pub fn format_version(&self) -> u16 {
        self.format_version
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn kdf(&self) -> &KdfConfig {
        &self.kdf
    }

    pub fn key_wrap(&self) -> &KeyWrap {
        &self.key_wrap
    }
    
    pub fn get_dek(
        &self,
        master_password: &str,
    ) -> Result<[u8; DEK_LEN], String> {
        let kek = self.derive_kek(master_password)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&kek)
            .map_err(|_| "KEK 长度错误".to_string())?;
        let vault_id = &self.vault_id;
        let aad = format!("private-vault|v1|{vault_id}|key-envelope");
        let xnonce = XNonce::try_from(self.key_wrap.nonce.as_slice())
            .map_err(|_| "Nonce 长度错误".to_string())?;
        let plaintext_dek = cipher
            .decrypt(
                &xnonce,
                Payload {
                    msg: &self.key_wrap.ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| "主密码错误或保险库信封已被篡改".to_string())?;
        plaintext_dek
            .try_into()
            .map_err(|_| "解开的 DEK 长度错误".to_string())
    }
}

impl KdfConfig {
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn mem_cost_kib(&self) -> u32 {
        self.mem_cost_kib
    }

    pub fn time_cost(&self) -> u32 {
        self.time_cost
    }

    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            algorithm: String::from("argon2id"),
            salt: random_bytes::<SALT_LEN>()?.to_vec(),
            mem_cost_kib: 65_536,
            time_cost: 3,
            parallelism: 1,
        })
    }
}

impl KeyWrap {
    pub fn new(
        kek: &[u8; KEK_LEN],
        dek: &[u8; DEK_LEN],
        vault_id: &str,
    ) -> Result<Self, String> {
        let nonce = random_bytes::<NONCE_LEN>()?;

        let cipher = XChaCha20Poly1305::new_from_slice(kek)
            .map_err(|_| "KEK 长度错误".to_string())?;

        let aad = format!("private-vault|v1|{vault_id}|key-envelope");
        let xnonce = XNonce::try_from(nonce.as_slice())
            .map_err(|_| "Nonce 长度错误".to_string())?;
        let ciphertext = cipher
            .encrypt(
                &xnonce,
                Payload {
                    msg: dek,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| "DEK 加密失败".to_string())?;

        Ok(Self {
            algorithm: String::from("xchacha20poly1305"),
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    fill(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

