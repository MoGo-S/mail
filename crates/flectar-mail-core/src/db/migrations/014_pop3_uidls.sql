CREATE TABLE pop3_uidls (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    uidl TEXT NOT NULL,
    message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    PRIMARY KEY (account_id, uidl)
);
