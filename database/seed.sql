-- Example data for local development only.
-- These BLOB literals are placeholders with the expected binary shape; they are not real ciphertext.

PRAGMA foreign_keys = ON;

INSERT INTO vaults (vault_id, format_version)
VALUES ('demo-vault', 1);

INSERT INTO key_envelopes (
    envelope_id,
    vault_id,
    envelope_version,
    kdf_algorithm,
    salt,
    mem_cost_kib,
    time_cost,
    parallelism,
    wrap_algorithm,
    wrap_nonce,
    wrapped_dek_ciphertext
)
VALUES (
    'envelope-demo-001',
    'demo-vault',
    1,
    'argon2id',
    X'00112233445566778899AABBCCDDEEFF',
    65536,
    3,
    1,
    'xchacha20poly1305',
    X'000102030405060708090A0B0C0D0E0F1011121314151617',
    X'11223344556677889900AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
);

INSERT INTO people (
    person_id,
    vault_id,
    enc_name,
    enc_gender,
    enc_birthday,
    enc_note
)
VALUES
(
    'person-alice',
    'demo-vault',
    X'01000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    X'0102030405060708090A0B0C0D0E0F101112131415161718191A191A1B1C1D1E',
    X'010A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728',
    X'010B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223242526272829'
),
(
    'person-bob',
    'demo-vault',
    X'010C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A',
    X'010D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B',
    NULL,
    X'010E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C'
);

INSERT INTO person_aliases (
    alias_id,
    person_id,
    enc_alias,
    enc_alias_type
)
VALUES (
    'alias-alice-001',
    'person-alice',
    X'01101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E',
    X'011112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F'
);

INSERT INTO contact_methods (
    contact_id,
    person_id,
    enc_type,
    enc_value,
    enc_label,
    enc_is_primary
)
VALUES (
    'contact-alice-email',
    'person-alice',
    X'01202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E',
    X'012122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F',
    X'0122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40',
    X'01232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041'
);

INSERT INTO addresses (
    address_id,
    vault_id,
    enc_country,
    enc_region,
    enc_city,
    enc_postal_code,
    enc_street,
    enc_freeform_note
)
VALUES (
    'address-alice-home',
    'demo-vault',
    X'01303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E',
    X'013132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F',
    X'0132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F50',
    X'01333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F5051',
    X'013435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152',
    NULL
);

INSERT INTO person_addresses (
    person_address_id,
    person_id,
    address_id,
    enc_address_type,
    enc_valid_from,
    enc_valid_to,
    enc_note
)
VALUES (
    'person-address-alice-home',
    'person-alice',
    'address-alice-home',
    X'01505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E',
    X'015152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F',
    NULL,
    X'0152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70'
);

INSERT INTO introductions (
    introduction_id,
    vault_id,
    introduced_person_id,
    introduced_by_id,
    met_with_id,
    enc_context,
    enc_location,
    enc_met_on,
    enc_note
)
VALUES (
    'intro-alice-bob',
    'demo-vault',
    'person-bob',
    'person-alice',
    NULL,
    X'01606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E',
    X'016162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F',
    NULL,
    X'0162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F80'
);

INSERT INTO relationships (
    relationship_id,
    vault_id,
    person_a_id,
    person_b_id,
    enc_type,
    enc_direction,
    enc_started_on,
    enc_ended_on,
    enc_status,
    enc_note
)
VALUES (
    'relationship-alice-bob',
    'demo-vault',
    'person-alice',
    'person-bob',
    X'01707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E',
    NULL,
    NULL,
    NULL,
    X'017172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F',
    X'0172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90'
);

INSERT INTO interactions (
    interaction_id,
    vault_id,
    enc_occurred_at,
    enc_channel,
    enc_summary,
    enc_follow_up_on
)
VALUES (
    'interaction-demo-001',
    'demo-vault',
    X'01808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E',
    X'018182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F',
    X'0182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0',
    NULL
);

INSERT INTO interaction_people (interaction_id, person_id)
VALUES
    ('interaction-demo-001', 'person-alice'),
    ('interaction-demo-001', 'person-bob');

INSERT INTO credentials (
    credential_id,
    vault_id,
    enc_title,
    enc_url,
    enc_username,
    enc_password,
    enc_totp_secret,
    enc_note
)
VALUES (
    'credential-example-github',
    'demo-vault',
    X'01909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAE',
    X'019192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF',
    X'0192939495969798999A9B9C9D9EA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0',
    X'01939495969798999A9B9C9D9EA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1',
    NULL,
    X'019495969798999A9B9C9D9EA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2'
);

INSERT INTO secure_notes (
    note_id,
    vault_id,
    enc_title,
    enc_content
)
VALUES (
    'note-demo-001',
    'demo-vault',
    X'01A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBD',
    X'01A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBE'
);
