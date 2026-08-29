use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use getrandom::fill;
const KEK_LEN: usize = 32;
const DEK_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

pub struct KeyEnvelope  {
    format_version: u16,
    vault_id: String,
    kdf: KdfConfig,
    key_wrap: KeyWrap,
}

pub struct KdfConfig {
    algorithm: String,
    salt: Vec<u8>,
    mem_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
}

pub struct KeyWrap {
    algorithm: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl KeyEnvelope {
    pub fn new(
        master_password: &str,
        vault_id: String,
    ) -> Result<(Self, [u8; DEK_LEN]), String> {
        let kdf = KdfConfig::new()?;
        let kek = derive_kek(master_password, &kdf)?;
        let dek = random_bytes::<DEK_LEN>()?;
        let key_wrap = KeyWrap::new(&kek, &dek, &vault_id)?;

        let envelope = Self {
            format_version: 1,
            vault_id,
            kdf,
            key_wrap,
        };
        Ok((envelope, dek))
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

        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
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

fn derive_kek(
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