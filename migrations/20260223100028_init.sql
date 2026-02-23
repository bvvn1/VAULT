CRATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    dek_by_master_key TEXT NOT NULL,
    master_key_salt TEXT NOT NULL,
    master_key_nonce TEXT NOT NULL,
    dek_by_recovery_key TEXT NOT NULL,
    recovery_key_salt TEXT NOT NULL,
    recovery_key_nonce TEXT NOT NULL
);

--generirai DEK(klyuch za vsichko), koito se encryptva po 2 nachina i toi da encryptva vsichko ostanalo
