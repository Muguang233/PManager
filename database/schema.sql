-- SQLite schema for PassManager.
-- 所有 enc_* 字段格式：
-- [format_version: 1 byte | nonce: 24 bytes | ciphertext + tag]

PRAGMA foreign_keys = ON;

CREATE TABLE vaults (
    vault_id        TEXT PRIMARY KEY,
    format_version  INTEGER NOT NULL CHECK (format_version >= 1)
);

-- Local authorization cache. The future backend is the source of truth, but the
-- client must never enumerate vault files that are not assigned to this account.
CREATE TABLE account_vaults (
    account_id  TEXT NOT NULL,
    vault_id    TEXT NOT NULL,
    PRIMARY KEY (account_id, vault_id),
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE key_envelopes (
    envelope_id              TEXT PRIMARY KEY,
    vault_id                 TEXT NOT NULL UNIQUE,
    envelope_version         INTEGER NOT NULL CHECK (envelope_version >= 1),

    kdf_algorithm            TEXT NOT NULL,
    salt                     BLOB NOT NULL,
    mem_cost_kib             INTEGER NOT NULL CHECK (mem_cost_kib > 0),
    time_cost                INTEGER NOT NULL CHECK (time_cost > 0),
    parallelism              INTEGER NOT NULL CHECK (parallelism > 0),

    wrap_algorithm           TEXT NOT NULL,
    wrap_nonce               BLOB NOT NULL CHECK (length(wrap_nonce) = 24),
    wrapped_dek_ciphertext   BLOB NOT NULL,

    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE people (
    person_id        TEXT PRIMARY KEY,
    vault_id         TEXT NOT NULL,

    enc_name         BLOB NOT NULL,
    enc_gender       BLOB NOT NULL,
    enc_birthday     BLOB,
    enc_note         BLOB,

    revision         INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    is_deleted       INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),

    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE person_aliases (
    alias_id         TEXT PRIMARY KEY,
    person_id        TEXT NOT NULL,

    enc_alias        BLOB NOT NULL,
    enc_alias_type   BLOB,

    revision         INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    is_deleted       INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),

    FOREIGN KEY (person_id) REFERENCES people(person_id)
);

CREATE TABLE contact_methods (
    contact_id       TEXT PRIMARY KEY,
    person_id        TEXT NOT NULL,

    enc_type         BLOB NOT NULL,
    enc_value        BLOB NOT NULL,
    enc_label        BLOB,
    enc_is_primary   BLOB,

    revision         INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    is_deleted       INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),

    FOREIGN KEY (person_id) REFERENCES people(person_id)
);

CREATE TABLE addresses (
    address_id         TEXT PRIMARY KEY,
    vault_id           TEXT NOT NULL,

    enc_country        BLOB,
    enc_region         BLOB,
    enc_city           BLOB,
    enc_postal_code    BLOB,
    enc_street         BLOB,
    enc_freeform_note  BLOB,

    revision           INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    is_deleted         INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),

    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE person_addresses (
    person_address_id  TEXT PRIMARY KEY,
    person_id          TEXT NOT NULL,
    address_id         TEXT NOT NULL,

    enc_address_type   BLOB,
    enc_valid_from     BLOB,
    enc_valid_to       BLOB,
    enc_note           BLOB,

    revision           INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    is_deleted         INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),

    FOREIGN KEY (person_id) REFERENCES people(person_id),
    FOREIGN KEY (address_id) REFERENCES addresses(address_id)
);

CREATE TABLE introductions (
    introduction_id       TEXT PRIMARY KEY,
    vault_id              TEXT NOT NULL,

    introduced_person_id  TEXT NOT NULL,
    introduced_by_id      TEXT,
    met_with_id           TEXT,

    enc_context           BLOB,
    enc_location          BLOB,
    enc_met_on            BLOB,
    enc_note              BLOB,

    revision              INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    is_deleted            INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),

    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id),
    FOREIGN KEY (introduced_person_id) REFERENCES people(person_id),
    FOREIGN KEY (introduced_by_id) REFERENCES people(person_id),
    FOREIGN KEY (met_with_id) REFERENCES people(person_id)
);

CREATE TABLE relationships (
    relationship_id    TEXT PRIMARY KEY,
    vault_id           TEXT NOT NULL,

    person_a_id        TEXT NOT NULL,
    person_b_id        TEXT NOT NULL,

    enc_type           BLOB NOT NULL,
    enc_direction      BLOB,
    enc_started_on     BLOB,
    enc_ended_on       BLOB,
    enc_status         BLOB,
    enc_note           BLOB,

    revision           INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    is_deleted         INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),

    CHECK (person_a_id <> person_b_id),

    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id),
    FOREIGN KEY (person_a_id) REFERENCES people(person_id),
    FOREIGN KEY (person_b_id) REFERENCES people(person_id)
);

CREATE TABLE interactions (
    interaction_id     TEXT PRIMARY KEY,
    vault_id           TEXT NOT NULL,

    enc_occurred_at    BLOB,
    enc_channel        BLOB,
    enc_summary        BLOB,
    enc_follow_up_on   BLOB,

    revision           INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    is_deleted         INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),

    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE interaction_people (
    interaction_id     TEXT NOT NULL,
    person_id          TEXT NOT NULL,

    PRIMARY KEY (interaction_id, person_id),

    FOREIGN KEY (interaction_id) REFERENCES interactions(interaction_id),
    FOREIGN KEY (person_id) REFERENCES people(person_id)
);

CREATE TABLE credentials (
    credential_id      TEXT PRIMARY KEY,
    vault_id           TEXT NOT NULL,

    enc_title          BLOB NOT NULL,
    enc_url            BLOB,
    enc_username       BLOB,
    enc_password       BLOB NOT NULL,
    enc_totp_secret    BLOB,
    enc_note           BLOB,

    revision           INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    is_deleted         INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),

    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE TABLE secure_notes (
    note_id            TEXT PRIMARY KEY,
    vault_id           TEXT NOT NULL,

    enc_title          BLOB NOT NULL,
    enc_content        BLOB NOT NULL,

    revision           INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    is_deleted         INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),

    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

CREATE INDEX idx_people_vault
ON people(vault_id, is_deleted);

CREATE INDEX idx_contact_methods_person
ON contact_methods(person_id, is_deleted);

CREATE INDEX idx_relationships_person_a
ON relationships(person_a_id, is_deleted);

CREATE INDEX idx_relationships_person_b
ON relationships(person_b_id, is_deleted);

CREATE INDEX idx_interaction_people_person
ON interaction_people(person_id);
