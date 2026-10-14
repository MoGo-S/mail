-- Keep the receive protocol separate from the legacy mail_protocol column.
-- That column's CHECK constraint predates POP3 and is retained for old readers.
ALTER TABLE accounts
  ADD COLUMN incoming_protocol TEXT NOT NULL DEFAULT 'imap'
  CHECK (incoming_protocol IN ('imap', 'jmap', 'pop3'));

UPDATE accounts SET incoming_protocol = mail_protocol;
