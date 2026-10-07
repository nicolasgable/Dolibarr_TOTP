-- Copyright (C) 2026 AllSafe

ALTER TABLE llx_totpauth_user ADD UNIQUE INDEX uk_totpauth_user_fk_user (fk_user);
ALTER TABLE llx_totpauth_user ADD CONSTRAINT fk_totpauth_user_fk_user FOREIGN KEY (fk_user) REFERENCES llx_user (rowid) ON DELETE CASCADE;
