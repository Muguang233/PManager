mod key_envelope;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use getrandom::fill;
use key_envelope::{KeyEnvelope, validate_vault_id};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, sync::Mutex};
use tauri::State;
use zeroize::Zeroizing;

const DATABASE_SCHEMA: &str = include_str!("../../../database/schema.sql");
const ACCOUNT_SALT_LEN: usize = 16;
const ACCOUNT_HASH_LEN: usize = 32;
const FIELD_VERSION: u8 = 2;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AccountRecord {
    #[serde(default)]
    account_id: String,
    username: String,
    salt: Vec<u8>,
    password_hash: Vec<u8>,
}
#[derive(Debug, Serialize)]
struct AuthState {
    authenticated: bool,
    username: Option<String>,
    needs_registration: bool,
}
#[derive(Debug, Serialize)]
struct VaultSummary {
    vault_id: String,
    label: String,
    unlocked: bool,
}
#[derive(Debug, Serialize)]
struct UnlockResult {
    vault_id: String,
    status: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct CredentialInput {
    title: String,
    url: Option<String>,
    username: Option<String>,
    password: String,
    totp_secret: Option<String>,
    note: Option<String>,
}
#[derive(Debug, Serialize)]
struct Credential {
    credential_id: String,
    title: String,
    url: Option<String>,
    username: Option<String>,
    password: String,
    totp_secret: Option<String>,
    note: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct ContactInput {
    kind: String,
    value: String,
    label: Option<String>,
    is_primary: bool,
}
#[derive(Debug, Serialize)]
struct Contact {
    contact_id: String,
    kind: String,
    value: String,
    label: Option<String>,
    is_primary: bool,
}
#[derive(Debug, Serialize, Deserialize)]
struct PersonInput {
    name: String,
    gender: Option<String>,
    birthday: Option<String>,
    note: Option<String>,
    contacts: Vec<ContactInput>,
}
#[derive(Debug, Serialize)]
struct PersonSummary {
    person_id: String,
    name: String,
    gender: String,
    contact_count: i64,
}
#[derive(Debug, Serialize)]
struct Person {
    person_id: String,
    name: String,
    gender: String,
    birthday: Option<String>,
    note: Option<String>,
    contacts: Vec<Contact>,
}
struct Session {
    account_id: Option<String>,
    username: Option<String>,
    unlocked_vault: Option<String>,
    database: Option<Connection>,
    dek: Option<Zeroizing<[u8; 32]>>,
}
struct AppState {
    session: Mutex<Session>,
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn database_path() -> PathBuf {
    project_root().join("database/pass_manager.db")
}
fn accounts_path() -> PathBuf {
    project_root().join("cfg/accounts.json")
}
fn load_accounts() -> Result<Vec<AccountRecord>, String> {
    let path = accounts_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut accounts: Vec<AccountRecord> = serde_json::from_str(
        &fs::read_to_string(path).map_err(|e| format!("读取账户文件失败: {e}"))?,
    )
    .map_err(|e| format!("解析账户文件失败: {e}"))?;
    if accounts.iter().any(|account| account.account_id.is_empty()) {
        for account in &mut accounts {
            if account.account_id.is_empty() {
                account.account_id = random_id()?;
            }
        }
        save_accounts(&accounts)?;
    }
    Ok(accounts)
}
fn save_accounts(accounts: &[AccountRecord]) -> Result<(), String> {
    let path = accounts_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建账户目录失败: {e}"))?;
    }
    fs::write(
        path,
        serde_json::to_string_pretty(accounts).map_err(|e| format!("序列化账户失败: {e}"))?,
    )
    .map_err(|e| format!("保存账户失败: {e}"))
}
fn derive_account_hash(password: &str, salt: &[u8]) -> Result<[u8; ACCOUNT_HASH_LEN], String> {
    let params = Params::new(65_536, 3, 1, Some(ACCOUNT_HASH_LEN))
        .map_err(|e| format!("账户 KDF 参数错误: {e}"))?;
    let mut hash = [0u8; ACCOUNT_HASH_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut hash)
        .map_err(|e| format!("账户密码哈希失败: {e}"))?;
    Ok(hash)
}
fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
fn random_id() -> Result<String, String> {
    Ok(random_bytes::<16>()?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn ensure_database() -> Result<(), String> {
    let path = database_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建数据库目录失败: {e}"))?;
    }
    let connection = Connection::open(path).map_err(|e| format!("打开 SQLite 数据库失败: {e}"))?;
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'vaults')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("检查 SQLite schema 失败: {e}"))?;
    if !exists {
        connection
            .execute_batch(DATABASE_SCHEMA)
            .map_err(|e| format!("初始化 SQLite schema 失败: {e}"))?;
    } else {
        connection.execute_batch("CREATE TABLE IF NOT EXISTS account_vaults (account_id TEXT NOT NULL, vault_id TEXT NOT NULL, PRIMARY KEY (account_id, vault_id), FOREIGN KEY (vault_id) REFERENCES vaults(vault_id));").map_err(|e| format!("升级账户 vault 映射失败: {e}"))?;
    }
    Ok(())
}

// The decrypted database uses SQLite's :memory: VFS. No plaintext database, WAL,
// journal, or filename is ever created during unlock.
fn open_memory_copy() -> Result<Connection, String> {
    ensure_database()?;
    let connection =
        Connection::open_in_memory().map_err(|e| format!("创建内存数据库失败: {e}"))?;
    connection
        .execute(
            "ATTACH DATABASE ?1 AS encrypted_source",
            [database_path().to_string_lossy().as_ref()],
        )
        .map_err(|e| format!("读取加密数据库失败: {e}"))?;
    let objects: Vec<String> = connection.prepare("SELECT sql FROM encrypted_source.sqlite_master WHERE type IN ('table', 'index', 'trigger') AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END").map_err(|e| format!("读取数据库结构失败: {e}"))?.query_map([], |row| row.get(0)).map_err(|e| format!("读取数据库结构失败: {e}"))?.collect::<Result<_, _>>().map_err(|e| format!("读取数据库结构失败: {e}"))?;
    for sql in objects {
        connection
            .execute_batch(&sql)
            .map_err(|e| format!("复制数据库结构失败: {e}"))?;
    }
    let tables: Vec<String> = connection.prepare("SELECT name FROM encrypted_source.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").map_err(|e| format!("读取数据库表失败: {e}"))?.query_map([], |row| row.get(0)).map_err(|e| format!("读取数据库表失败: {e}"))?.collect::<Result<_, _>>().map_err(|e| format!("读取数据库表失败: {e}"))?;
    for table in tables {
        let escaped = table.replace('"', "\"\"");
        connection
            .execute_batch(&format!(
                "INSERT INTO \"{escaped}\" SELECT * FROM encrypted_source.\"{escaped}\""
            ))
            .map_err(|e| format!("复制数据库内容失败: {e}"))?;
    }
    connection
        .execute_batch("DETACH DATABASE encrypted_source")
        .map_err(|e| format!("关闭加密数据库失败: {e}"))?;
    Ok(connection)
}

fn field_aad(vault_id: &str, table: &str, record_id: &str, column: &str) -> Vec<u8> {
    format!("passmanager|field-v2|{vault_id}|{table}|{record_id}|{column}").into_bytes()
}
fn encrypt_field(
    dek: &[u8; 32],
    vault_id: &str,
    table: &str,
    record_id: &str,
    column: &str,
    plaintext: &str,
) -> Result<Vec<u8>, String> {
    let nonce = random_bytes::<24>()?;
    let cipher = XChaCha20Poly1305::new_from_slice(dek).map_err(|_| "DEK 长度错误".to_string())?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &field_aad(vault_id, table, record_id, column),
            },
        )
        .map_err(|_| "字段加密失败".to_string())?;
    let mut encoded = vec![FIELD_VERSION];
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}
fn decrypt_field(
    dek: &[u8; 32],
    vault_id: &str,
    table: &str,
    record_id: &str,
    column: &str,
    encrypted: &[u8],
) -> Result<Vec<u8>, String> {
    if encrypted.len() < 41 || encrypted[0] != FIELD_VERSION {
        return Err("字段密文版本无效；旧版或损坏数据不可安全解锁".to_string());
    }
    let cipher = XChaCha20Poly1305::new_from_slice(dek).map_err(|_| "DEK 长度错误".to_string())?;
    cipher
        .decrypt(
            XNonce::from_slice(&encrypted[1..25]),
            Payload {
                msg: &encrypted[25..],
                aad: &field_aad(vault_id, table, record_id, column),
            },
        )
        .map_err(|_| "字段解密失败或数据已被篡改".to_string())
}
type EncCredential = (
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
fn decrypt_credentials(
    connection: &mut Connection,
    dek: &[u8; 32],
    vault_id: &str,
) -> Result<(), String> {
    let rows: Vec<(String, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> = connection.prepare("SELECT credential_id,enc_title,enc_url,enc_username,enc_password,enc_totp_secret,enc_note FROM credentials WHERE vault_id=?1 AND is_deleted=0").map_err(|e| format!("读取凭据失败: {e}"))?.query_map([vault_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).map_err(|e| format!("读取凭据失败: {e}"))?.collect::<Result<_, _>>().map_err(|e| format!("读取凭据失败: {e}"))?;
    let tx = connection
        .transaction()
        .map_err(|e| format!("开启内存事务失败: {e}"))?;
    for (id, title, url, username, password, totp, note) in rows {
        let opt = |column: &str, value: Option<Vec<u8>>| {
            value
                .map(|v| decrypt_field(dek, vault_id, "credentials", &id, column, &v))
                .transpose()
        };
        tx.execute("UPDATE credentials SET enc_title=?1,enc_url=?2,enc_username=?3,enc_password=?4,enc_totp_secret=?5,enc_note=?6 WHERE credential_id=?7", params![decrypt_field(dek,vault_id,"credentials",&id,"enc_title",&title)?,opt("enc_url",url)?,opt("enc_username",username)?,decrypt_field(dek,vault_id,"credentials",&id,"enc_password",&password)?,opt("enc_totp_secret",totp)?,opt("enc_note",note)?,id]).map_err(|e| format!("写入内存凭据失败: {e}"))?;
    }
    tx.commit().map_err(|e| format!("提交内存事务失败: {e}"))
}
fn required_session(session: &Session) -> Result<(&str, &[u8; 32]), String> {
    Ok((
        session
            .unlocked_vault
            .as_deref()
            .ok_or_else(|| "请先解锁 vault".to_string())?,
        session
            .dek
            .as_deref()
            .ok_or_else(|| "请先解锁 vault".to_string())?,
    ))
}
fn validate_credential(input: &CredentialInput) -> Result<(), String> {
    if input.title.trim().is_empty() || input.password.is_empty() {
        Err("标题和密码不能为空".to_string())
    } else {
        Ok(())
    }
}
fn encrypt_credential(
    input: &CredentialInput,
    dek: &[u8; 32],
    vault_id: &str,
    id: &str,
) -> Result<EncCredential, String> {
    let optional = |column: &str, value: &Option<String>| {
        value
            .as_deref()
            .filter(|v| !v.is_empty())
            .map(|v| encrypt_field(dek, vault_id, "credentials", id, column, v))
            .transpose()
    };
    Ok((
        encrypt_field(dek, vault_id, "credentials", id, "enc_title", &input.title)?,
        optional("enc_url", &input.url)?,
        optional("enc_username", &input.username)?,
        encrypt_field(
            dek,
            vault_id,
            "credentials",
            id,
            "enc_password",
            &input.password,
        )?,
        optional("enc_totp_secret", &input.totp_secret)?,
        optional("enc_note", &input.note)?,
    ))
}
fn optional_bytes(value: &Option<String>) -> Option<&[u8]> {
    value
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(str::as_bytes)
}
fn text(value: Option<Vec<u8>>) -> Option<String> {
    value.map(|v| String::from_utf8(v).unwrap_or_default())
}
fn decrypt_people(
    connection: &mut Connection,
    dek: &[u8; 32],
    vault_id: &str,
) -> Result<(), String> {
    let people: Vec<(String,Vec<u8>,Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>)> = connection.prepare("SELECT person_id,enc_name,enc_gender,enc_birthday,enc_note FROM people WHERE vault_id=?1 AND is_deleted=0").map_err(|e| format!("读取联系人失败: {e}"))?.query_map([vault_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(|e| format!("读取联系人失败: {e}"))?.collect::<Result<_,_>>().map_err(|e| format!("读取联系人失败: {e}"))?;
    let contacts: Vec<(String,Vec<u8>,Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>)> = connection.prepare("SELECT c.contact_id,c.enc_type,c.enc_value,c.enc_label,c.enc_is_primary FROM contact_methods c JOIN people p ON p.person_id=c.person_id WHERE p.vault_id=?1 AND c.is_deleted=0 AND p.is_deleted=0").map_err(|e| format!("读取联系方式失败: {e}"))?.query_map([vault_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(|e| format!("读取联系方式失败: {e}"))?.collect::<Result<_,_>>().map_err(|e| format!("读取联系方式失败: {e}"))?;
    let tx = connection
        .transaction()
        .map_err(|e| format!("开启联系人内存事务失败: {e}"))?;
    for (id, name, gender, birthday, note) in people {
        let opt = |column: &str, value: Option<Vec<u8>>| {
            value
                .map(|v| decrypt_field(dek, vault_id, "people", &id, column, &v))
                .transpose()
        };
        tx.execute("UPDATE people SET enc_name=?1,enc_gender=?2,enc_birthday=?3,enc_note=?4 WHERE person_id=?5",params![decrypt_field(dek,vault_id,"people",&id,"enc_name",&name)?,decrypt_field(dek,vault_id,"people",&id,"enc_gender",&gender)?,opt("enc_birthday",birthday)?,opt("enc_note",note)?,id]).map_err(|e| format!("写入内存联系人失败: {e}"))?;
    }
    for (id, kind, value, label, primary) in contacts {
        let opt = |column: &str, value: Option<Vec<u8>>| {
            value
                .map(|v| decrypt_field(dek, vault_id, "contact_methods", &id, column, &v))
                .transpose()
        };
        tx.execute("UPDATE contact_methods SET enc_type=?1,enc_value=?2,enc_label=?3,enc_is_primary=?4 WHERE contact_id=?5",params![decrypt_field(dek,vault_id,"contact_methods",&id,"enc_type",&kind)?,decrypt_field(dek,vault_id,"contact_methods",&id,"enc_value",&value)?,opt("enc_label",label)?,opt("enc_is_primary",primary)?,id]).map_err(|e| format!("写入内存联系方式失败: {e}"))?;
    }
    tx.commit()
        .map_err(|e| format!("提交联系人内存事务失败: {e}"))
}
fn validate_person(input: &PersonInput) -> Result<(), String> {
    if input.name.trim().is_empty() {
        return Err("联系人姓名不能为空".to_string());
    }
    if input
        .contacts
        .iter()
        .any(|c| c.kind.trim().is_empty() || c.value.trim().is_empty())
    {
        return Err("联系方式的类型和值不能为空".to_string());
    }
    Ok(())
}
fn insert_contacts(
    connection: &Connection,
    vault_id: &str,
    person_id: &str,
    dek: &[u8; 32],
    contacts: &[ContactInput],
    plaintext: bool,
) -> Result<(), String> {
    for contact in contacts {
        let id = random_id()?;
        if plaintext {
            connection.execute("INSERT INTO contact_methods (contact_id,person_id,enc_type,enc_value,enc_label,enc_is_primary) VALUES (?1,?2,?3,?4,?5,?6)",params![id,person_id,contact.kind.as_bytes(),contact.value.as_bytes(),optional_bytes(&contact.label),if contact.is_primary { Some("1".as_bytes()) } else { Some("0".as_bytes()) }]).map_err(|e| format!("写入内存联系方式失败: {e}"))?;
        } else {
            let label = contact
                .label
                .as_deref()
                .filter(|v| !v.is_empty())
                .map(|v| encrypt_field(dek, vault_id, "contact_methods", &id, "enc_label", v))
                .transpose()?;
            connection.execute("INSERT INTO contact_methods (contact_id,person_id,enc_type,enc_value,enc_label,enc_is_primary) VALUES (?1,?2,?3,?4,?5,?6)",params![id,person_id,encrypt_field(dek,vault_id,"contact_methods",&id,"enc_type",&contact.kind)?,encrypt_field(dek,vault_id,"contact_methods",&id,"enc_value",&contact.value)?,label,encrypt_field(dek,vault_id,"contact_methods",&id,"enc_is_primary",if contact.is_primary { "1" } else { "0" })?]).map_err(|e| format!("保存联系方式失败: {e}"))?;
        }
    }
    Ok(())
}

#[tauri::command]
fn auth_state(state: State<'_, AppState>) -> Result<AuthState, String> {
    let accounts = load_accounts()?;
    let session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    Ok(AuthState {
        authenticated: session.username.is_some(),
        username: session.username.clone(),
        needs_registration: accounts.is_empty(),
    })
}
#[tauri::command]
fn register_account(
    username: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<AuthState, String> {
    let username = username.trim().to_lowercase();
    if username.is_empty() || password.len() < 8 {
        return Err("账户名不能为空，密码至少需要 8 个字符".to_string());
    }
    let mut accounts = load_accounts()?;
    if accounts.iter().any(|a| a.username == username) {
        return Err("账户已存在，请直接登录".to_string());
    }
    let salt = random_bytes::<ACCOUNT_SALT_LEN>()?;
    let account_id = random_id()?;
    accounts.push(AccountRecord {
        account_id: account_id.clone(),
        username: username.clone(),
        salt: salt.to_vec(),
        password_hash: derive_account_hash(&password, &salt)?.to_vec(),
    });
    save_accounts(&accounts)?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    session.account_id = Some(account_id);
    session.username = Some(username.clone());
    Ok(AuthState {
        authenticated: true,
        username: Some(username),
        needs_registration: false,
    })
}
#[tauri::command]
fn login(
    username: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<AuthState, String> {
    let username = username.trim().to_lowercase();
    let account = load_accounts()?
        .into_iter()
        .find(|a| a.username == username)
        .ok_or_else(|| "账户不存在：请先注册或检查账户名".to_string())?;
    if derive_account_hash(&password, &account.salt)?.as_slice() != account.password_hash.as_slice()
    {
        return Err("密码错误：请重新输入".to_string());
    }
    if account.account_id.is_empty() {
        return Err("账户记录缺少 account_id；请重新注册".to_string());
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    session.account_id = Some(account.account_id);
    session.username = Some(username.clone());
    Ok(AuthState {
        authenticated: true,
        username: Some(username),
        needs_registration: false,
    })
}
#[tauri::command]
fn list_vaults(state: State<'_, AppState>) -> Result<Vec<VaultSummary>, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    let account_id = session
        .account_id
        .clone()
        .ok_or_else(|| "请先登录账户".to_string())?;
    let active = session.unlocked_vault.clone();
    drop(session);
    ensure_database()?;
    let connection =
        Connection::open(database_path()).map_err(|e| format!("打开加密数据库失败: {e}"))?;
    let ids: Vec<String> = connection
        .prepare("SELECT vault_id FROM account_vaults WHERE account_id=?1 ORDER BY vault_id")
        .map_err(|e| format!("读取 vault 授权失败: {e}"))?
        .query_map([account_id], |r| r.get(0))
        .map_err(|e| format!("读取 vault 授权失败: {e}"))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("读取 vault 授权失败: {e}"))?;
    Ok(ids
        .into_iter()
        .filter_map(|id| {
            KeyEnvelope::from_vault_file(&id)
                .ok()
                .map(|_| VaultSummary {
                    label: id.clone(),
                    unlocked: active.as_deref() == Some(&id),
                    vault_id: id,
                })
        })
        .collect())
}
#[tauri::command]
fn create_vault(
    vault_id: String,
    master_password: String,
    state: State<'_, AppState>,
) -> Result<VaultSummary, String> {
    let account_id = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?
        .account_id
        .clone()
        .ok_or_else(|| "请先登录账户".to_string())?;
    validate_vault_id(&vault_id)?;
    if master_password.is_empty() {
        return Err("vault 主密码不能为空".to_string());
    }
    let path = KeyEnvelope::vault_file_path(&vault_id)?;
    if path.exists() {
        return Err("vault 已存在".to_string());
    }
    ensure_database()?;
    let envelope = KeyEnvelope::new(&master_password, vault_id.clone())?;
    envelope.save_to_vault_file()?;
    let connection = Connection::open(database_path()).map_err(|e| e.to_string())?;
    if let Err(e) = connection
        .execute_batch("BEGIN IMMEDIATE")
        .and_then(|_| {
            connection.execute(
                "INSERT INTO vaults (vault_id,format_version) VALUES (?1,1)",
                [&vault_id],
            )
        })
        .and_then(|_| {
            connection.execute(
                "INSERT INTO account_vaults (account_id,vault_id) VALUES (?1,?2)",
                params![account_id, vault_id],
            )
        })
        .and_then(|_| connection.execute_batch("COMMIT"))
    {
        let _ = connection.execute_batch("ROLLBACK");
        let _ = fs::remove_file(path);
        return Err(format!("创建 vault 授权记录失败: {e}"));
    }
    Ok(VaultSummary {
        label: vault_id.clone(),
        vault_id,
        unlocked: false,
    })
}
#[tauri::command]
fn unlock_vault(
    vault_id: String,
    master_password: String,
    state: State<'_, AppState>,
) -> Result<UnlockResult, String> {
    let account_id = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?
        .account_id
        .clone()
        .ok_or_else(|| "请先登录账户".to_string())?;
    ensure_database()?;
    let authorized: bool = Connection::open(database_path())
        .map_err(|e| format!("打开加密数据库失败: {e}"))?
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM account_vaults WHERE account_id=?1 AND vault_id=?2)",
            params![account_id, vault_id],
            |r| r.get(0),
        )
        .map_err(|e| format!("检查 vault 授权失败: {e}"))?;
    if !authorized {
        return Err("当前账户未被授权访问此 vault".to_string());
    };
    let envelope = KeyEnvelope::from_vault_file(&vault_id)?;
    let dek = Zeroizing::new(envelope.get_dek(&master_password)?);
    let mut database = open_memory_copy()?;
    decrypt_credentials(&mut database, &dek, &vault_id)?;
    decrypt_people(&mut database, &dek, &vault_id)?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    session.database = Some(database);
    session.dek = Some(dek);
    session.unlocked_vault = Some(vault_id.clone());
    Ok(UnlockResult {
        vault_id,
        status: "Unlocked in memory; no plaintext database is written to disk".to_string(),
    })
}
#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    session.database = None;
    session.dek = None;
    session.unlocked_vault = None;
    Ok(())
}
#[tauri::command]
fn list_credentials(query: String, state: State<'_, AppState>) -> Result<Vec<Credential>, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    let (vault_id, _) = required_session(&session)?;
    let db = session
        .database
        .as_ref()
        .ok_or_else(|| "请先解锁 vault".to_string())?;
    let pattern = format!("%{}%", query.trim());
    let mut stmt = db.prepare("SELECT credential_id,enc_title,enc_url,enc_username,enc_password,enc_totp_secret,enc_note FROM credentials WHERE vault_id=?1 AND is_deleted=0 AND (CAST(enc_title AS TEXT) LIKE ?2 OR CAST(enc_url AS TEXT) LIKE ?2 OR CAST(enc_username AS TEXT) LIKE ?2) ORDER BY CAST(enc_title AS TEXT)").map_err(|e| format!("查询凭据失败: {e}"))?;
    stmt.query_map(params![vault_id, pattern], |r| {
        Ok(Credential {
            credential_id: r.get(0)?,
            title: String::from_utf8(r.get::<_, Vec<u8>>(1)?).unwrap_or_default(),
            url: r
                .get::<_, Option<Vec<u8>>>(2)?
                .map(|v| String::from_utf8(v).unwrap_or_default()),
            username: r
                .get::<_, Option<Vec<u8>>>(3)?
                .map(|v| String::from_utf8(v).unwrap_or_default()),
            password: String::from_utf8(r.get::<_, Vec<u8>>(4)?).unwrap_or_default(),
            totp_secret: r
                .get::<_, Option<Vec<u8>>>(5)?
                .map(|v| String::from_utf8(v).unwrap_or_default()),
            note: r
                .get::<_, Option<Vec<u8>>>(6)?
                .map(|v| String::from_utf8(v).unwrap_or_default()),
        })
    })
    .map_err(|e| format!("查询凭据失败: {e}"))?
    .collect::<Result<_, _>>()
    .map_err(|e| format!("查询凭据失败: {e}"))
}
#[tauri::command]
fn list_people(query: String, state: State<'_, AppState>) -> Result<Vec<PersonSummary>, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    let (vault_id, _) = required_session(&session)?;
    let db = session
        .database
        .as_ref()
        .ok_or_else(|| "请先解锁 vault".to_string())?;
    let pattern = format!("%{}%", query.trim());
    let mut stmt = db.prepare("SELECT p.person_id,p.enc_name,p.enc_gender,COUNT(c.contact_id) FROM people p LEFT JOIN contact_methods c ON c.person_id=p.person_id AND c.is_deleted=0 WHERE p.vault_id=?1 AND p.is_deleted=0 AND (CAST(p.enc_name AS TEXT) LIKE ?2 OR EXISTS (SELECT 1 FROM contact_methods cm WHERE cm.person_id=p.person_id AND cm.is_deleted=0 AND CAST(cm.enc_value AS TEXT) LIKE ?2)) GROUP BY p.person_id ORDER BY CAST(p.enc_name AS TEXT)").map_err(|e| format!("查询联系人失败: {e}"))?;
    stmt.query_map(params![vault_id, pattern], |r| {
        Ok(PersonSummary {
            person_id: r.get(0)?,
            name: String::from_utf8(r.get::<_, Vec<u8>>(1)?).unwrap_or_default(),
            gender: String::from_utf8(r.get::<_, Vec<u8>>(2)?).unwrap_or_default(),
            contact_count: r.get(3)?,
        })
    })
    .map_err(|e| format!("查询联系人失败: {e}"))?
    .collect::<Result<_, _>>()
    .map_err(|e| format!("查询联系人失败: {e}"))
}
#[tauri::command]
fn get_person(person_id: String, state: State<'_, AppState>) -> Result<Person, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    let (vault_id, _) = required_session(&session)?;
    let db = session
        .database
        .as_ref()
        .ok_or_else(|| "请先解锁 vault".to_string())?;
    let (name,gender,birthday,note):(Vec<u8>,Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>) = db.query_row("SELECT enc_name,enc_gender,enc_birthday,enc_note FROM people WHERE person_id=?1 AND vault_id=?2 AND is_deleted=0",params![person_id,vault_id],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|_| "联系人不存在".to_string())?;
    let contacts = db.prepare("SELECT contact_id,enc_type,enc_value,enc_label,enc_is_primary FROM contact_methods WHERE person_id=?1 AND is_deleted=0 ORDER BY CAST(enc_is_primary AS TEXT) DESC").map_err(|e| format!("读取联系方式失败: {e}"))?.query_map([&person_id], |r| Ok(Contact { contact_id:r.get(0)?,kind:String::from_utf8(r.get::<_,Vec<u8>>(1)?).unwrap_or_default(),value:String::from_utf8(r.get::<_,Vec<u8>>(2)?).unwrap_or_default(),label:text(r.get(3)?),is_primary:text(r.get(4)?).as_deref()==Some("1") })).map_err(|e| format!("读取联系方式失败: {e}"))?.collect::<Result<Vec<_>,_>>().map_err(|e| format!("读取联系方式失败: {e}"))?;
    Ok(Person {
        person_id,
        name: String::from_utf8(name).unwrap_or_default(),
        gender: String::from_utf8(gender).unwrap_or_default(),
        birthday: text(birthday),
        note: text(note),
        contacts,
    })
}
#[tauri::command]
fn create_person(input: PersonInput, state: State<'_, AppState>) -> Result<Person, String> {
    validate_person(&input)?;
    let id = random_id()?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    let (vault, dek) = {
        let (v, d) = required_session(&session)?;
        (v.to_string(), *d)
    };
    let gender = input
        .gender
        .clone()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "未设置".to_string());
    let disk = Connection::open(database_path()).map_err(|e| format!("打开加密数据库失败: {e}"))?;
    disk.execute("INSERT INTO people (person_id,vault_id,enc_name,enc_gender,enc_birthday,enc_note) VALUES (?1,?2,?3,?4,?5,?6)",params![id,vault,encrypt_field(&dek,&vault,"people",&id,"enc_name",&input.name)?,encrypt_field(&dek,&vault,"people",&id,"enc_gender",&gender)?,input.birthday.as_deref().filter(|v|!v.is_empty()).map(|v|encrypt_field(&dek,&vault,"people",&id,"enc_birthday",v)).transpose()?,input.note.as_deref().filter(|v|!v.is_empty()).map(|v|encrypt_field(&dek,&vault,"people",&id,"enc_note",v)).transpose()?]).map_err(|e|format!("保存联系人失败: {e}"))?;
    insert_contacts(&disk, &vault, &id, &dek, &input.contacts, false)?;
    let db = session
        .database
        .as_mut()
        .ok_or_else(|| "请先解锁 vault".to_string())?;
    db.execute("INSERT INTO people (person_id,vault_id,enc_name,enc_gender,enc_birthday,enc_note) VALUES (?1,?2,?3,?4,?5,?6)",params![id,vault,input.name.as_bytes(),gender.as_bytes(),optional_bytes(&input.birthday),optional_bytes(&input.note)]).map_err(|e|format!("写入内存联系人失败: {e}"))?;
    insert_contacts(db, &vault, &id, &dek, &input.contacts, true)?;
    Ok(Person {
        person_id: id,
        name: input.name,
        gender,
        birthday: input.birthday.filter(|v| !v.is_empty()),
        note: input.note.filter(|v| !v.is_empty()),
        contacts: Vec::new(),
    })
}
#[tauri::command]
fn update_person(
    person_id: String,
    input: PersonInput,
    state: State<'_, AppState>,
) -> Result<(), String> {
    validate_person(&input)?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    let (vault, dek) = {
        let (v, d) = required_session(&session)?;
        (v.to_string(), *d)
    };
    let gender = input
        .gender
        .clone()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "未设置".to_string());
    let disk = Connection::open(database_path()).map_err(|e| format!("打开加密数据库失败: {e}"))?;
    if disk.execute("UPDATE people SET enc_name=?1,enc_gender=?2,enc_birthday=?3,enc_note=?4,revision=revision+1 WHERE person_id=?5 AND vault_id=?6 AND is_deleted=0",params![encrypt_field(&dek,&vault,"people",&person_id,"enc_name",&input.name)?,encrypt_field(&dek,&vault,"people",&person_id,"enc_gender",&gender)?,input.birthday.as_deref().filter(|v|!v.is_empty()).map(|v|encrypt_field(&dek,&vault,"people",&person_id,"enc_birthday",v)).transpose()?,input.note.as_deref().filter(|v|!v.is_empty()).map(|v|encrypt_field(&dek,&vault,"people",&person_id,"enc_note",v)).transpose()?,person_id,vault]).map_err(|e|format!("更新联系人失败: {e}"))?!=1{return Err("联系人不存在".to_string())};
    disk.execute(
        "UPDATE contact_methods SET is_deleted=1 WHERE person_id=?1",
        [&person_id],
    )
    .map_err(|e| format!("更新联系方式失败: {e}"))?;
    insert_contacts(&disk, &vault, &person_id, &dek, &input.contacts, false)?;
    let db = session
        .database
        .as_mut()
        .ok_or_else(|| "请先解锁 vault".to_string())?;
    db.execute("UPDATE people SET enc_name=?1,enc_gender=?2,enc_birthday=?3,enc_note=?4,revision=revision+1 WHERE person_id=?5",params![input.name.as_bytes(),gender.as_bytes(),optional_bytes(&input.birthday),optional_bytes(&input.note),person_id]).map_err(|e|format!("更新内存联系人失败: {e}"))?;
    db.execute(
        "DELETE FROM contact_methods WHERE person_id=?1",
        [&person_id],
    )
    .map_err(|e| format!("更新内存联系方式失败: {e}"))?;
    insert_contacts(db, &vault, &person_id, &dek, &input.contacts, true)?;
    Ok(())
}
#[tauri::command]
fn delete_person(person_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    let (vault, _) = required_session(&session)?;
    let disk = Connection::open(database_path()).map_err(|e| format!("打开加密数据库失败: {e}"))?;
    if disk.execute("UPDATE people SET is_deleted=1,revision=revision+1 WHERE person_id=?1 AND vault_id=?2 AND is_deleted=0",params![person_id,vault]).map_err(|e|format!("删除联系人失败: {e}"))?!=1{return Err("联系人不存在".to_string())};
    disk.execute(
        "UPDATE contact_methods SET is_deleted=1 WHERE person_id=?1",
        [&person_id],
    )
    .map_err(|e| format!("删除联系方式失败: {e}"))?;
    session
        .database
        .as_mut()
        .ok_or_else(|| "请先解锁 vault".to_string())?
        .execute(
            "UPDATE people SET is_deleted=1 WHERE person_id=?1",
            [person_id],
        )
        .map_err(|e| format!("更新内存联系人失败: {e}"))?;
    Ok(())
}
#[tauri::command]
fn create_credential(
    input: CredentialInput,
    state: State<'_, AppState>,
) -> Result<Credential, String> {
    validate_credential(&input)?;
    let id = random_id()?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    let (vault_id, dek) = {
        let (vault_id, dek) = required_session(&session)?;
        (vault_id.to_string(), *dek)
    };
    let values = encrypt_credential(&input, &dek, &vault_id, &id)?;
    let disk = Connection::open(database_path()).map_err(|e| format!("打开加密数据库失败: {e}"))?;
    disk.execute("INSERT INTO credentials (credential_id,vault_id,enc_title,enc_url,enc_username,enc_password,enc_totp_secret,enc_note) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![id,vault_id,values.0,values.1,values.2,values.3,values.4,values.5]).map_err(|e| format!("保存凭据失败: {e}"))?;
    session.database.as_mut().ok_or_else(|| "请先解锁 vault".to_string())?.execute("INSERT INTO credentials (credential_id,vault_id,enc_title,enc_url,enc_username,enc_password,enc_totp_secret,enc_note) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![id,vault_id,input.title.as_bytes(),optional_bytes(&input.url),optional_bytes(&input.username),input.password.as_bytes(),optional_bytes(&input.totp_secret),optional_bytes(&input.note)]).map_err(|e| format!("更新内存凭据失败: {e}"))?;
    Ok(Credential {
        credential_id: id,
        title: input.title,
        url: input.url.filter(|v| !v.is_empty()),
        username: input.username.filter(|v| !v.is_empty()),
        password: input.password,
        totp_secret: input.totp_secret.filter(|v| !v.is_empty()),
        note: input.note.filter(|v| !v.is_empty()),
    })
}
#[tauri::command]
fn update_credential(
    credential_id: String,
    input: CredentialInput,
    state: State<'_, AppState>,
) -> Result<(), String> {
    validate_credential(&input)?;
    let mut session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    let (vault_id, dek) = {
        let (vault_id, dek) = required_session(&session)?;
        (vault_id.to_string(), *dek)
    };
    let values = encrypt_credential(&input, &dek, &vault_id, &credential_id)?;
    let disk = Connection::open(database_path()).map_err(|e| format!("打开加密数据库失败: {e}"))?;
    if disk.execute("UPDATE credentials SET enc_title=?1,enc_url=?2,enc_username=?3,enc_password=?4,enc_totp_secret=?5,enc_note=?6,revision=revision+1 WHERE credential_id=?7 AND vault_id=?8 AND is_deleted=0",params![values.0,values.1,values.2,values.3,values.4,values.5,credential_id,vault_id]).map_err(|e| format!("更新凭据失败: {e}"))? != 1 { return Err("凭据不存在".to_string()); }
    session.database.as_mut().ok_or_else(|| "请先解锁 vault".to_string())?.execute("UPDATE credentials SET enc_title=?1,enc_url=?2,enc_username=?3,enc_password=?4,enc_totp_secret=?5,enc_note=?6,revision=revision+1 WHERE credential_id=?7",params![input.title.as_bytes(),optional_bytes(&input.url),optional_bytes(&input.username),input.password.as_bytes(),optional_bytes(&input.totp_secret),optional_bytes(&input.note),credential_id]).map_err(|e| format!("更新内存凭据失败: {e}"))?;
    Ok(())
}
#[tauri::command]
fn delete_credential(credential_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "会话锁定失败".to_string())?;
    let (vault_id, _) = required_session(&session)?;
    let disk = Connection::open(database_path()).map_err(|e| format!("打开加密数据库失败: {e}"))?;
    if disk.execute("UPDATE credentials SET is_deleted=1,revision=revision+1 WHERE credential_id=?1 AND vault_id=?2 AND is_deleted=0",params![credential_id,vault_id]).map_err(|e| format!("删除凭据失败: {e}"))? != 1 { return Err("凭据不存在".to_string()); }
    session
        .database
        .as_mut()
        .ok_or_else(|| "请先解锁 vault".to_string())?
        .execute(
            "UPDATE credentials SET is_deleted=1,revision=revision+1 WHERE credential_id=?1",
            [credential_id],
        )
        .map_err(|e| format!("更新内存凭据失败: {e}"))?;
    Ok(())
}
fn main() {
    tauri::Builder::default()
        .manage(AppState {
            session: Mutex::new(Session {
                account_id: None,
                username: None,
                unlocked_vault: None,
                database: None,
                dek: None,
            }),
        })
        .invoke_handler(tauri::generate_handler![
            auth_state,
            register_account,
            login,
            list_vaults,
            create_vault,
            unlock_vault,
            lock_vault,
            list_people,
            get_person,
            create_person,
            update_person,
            delete_person,
            list_credentials,
            create_credential,
            update_credential,
            delete_credential
        ])
        .run(tauri::generate_context!())
        .expect("error while running PassManager");
}
