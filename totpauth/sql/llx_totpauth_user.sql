-- Copyright (C) 2026 AllSafe
-- TOTP second factor, one row per Dolibarr user.

CREATE TABLE llx_totpauth_user
(
	rowid            integer AUTO_INCREMENT PRIMARY KEY NOT NULL,
	fk_user          integer NOT NULL,
	secret           varchar(255) NOT NULL,          -- Base32 secret, encrypted with dolEncrypt() when available
	status           smallint DEFAULT 0 NOT NULL,     -- 0 = enrollment in progress, 1 = active
	backup_codes     text NULL,                       -- JSON array of password_hash() of unused recovery codes
	last_timestep    bigint DEFAULT 0 NOT NULL,       -- Anti-replay: last accepted TOTP time step
	fail_count       integer DEFAULT 0 NOT NULL,      -- Consecutive failed attempts
	date_lastfail    datetime NULL,
	date_creation    datetime NOT NULL,
	date_activation  datetime NULL,
	date_lastuse     datetime NULL,
	tms              timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=innodb;
