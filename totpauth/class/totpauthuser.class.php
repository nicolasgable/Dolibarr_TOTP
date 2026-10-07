<?php
/* Copyright (C) 2026 AllSafe
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * \file    totpauth/class/totpauthuser.class.php
 * \ingroup totpauth
 * \brief   TOTP enrollment of one Dolibarr user (table llx_totpauth_user).
 */

require_once __DIR__.'/totp.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/security.lib.php';

class TotpAuthUser
{
	const STATUS_ENROLLING = 0;
	const STATUS_ACTIVE    = 1;

	const VERIFY_OK        = 1;
	const VERIFY_OK_BACKUP = 2;
	const VERIFY_BAD       = 0;
	const VERIFY_LOCKED    = -2;

	const NB_BACKUP_CODES  = 10;

	/** @var DoliDB */
	public $db;
	public $error = '';

	public $id = 0;
	public $fk_user = 0;
	/** @var string Clear Base32 secret (decrypted in memory only) */
	public $secret = '';
	public $status = self::STATUS_ENROLLING;
	/** @var string[] password_hash() of the unused recovery codes */
	public $backup_codes = array();
	public $last_timestep = 0;
	public $fail_count = 0;
	public $date_lastfail = null;
	public $date_creation = null;
	public $date_activation = null;
	public $date_lastuse = null;

	/**
	 * @param DoliDB $db Database handler
	 */
	public function __construct($db)
	{
		$this->db = $db;
	}

	/**
	 * @return string Table name with prefix
	 */
	private static function table()
	{
		return MAIN_DB_PREFIX.'totpauth_user';
	}

	/**
	 * Encrypt the secret before storing it (dolEncrypt exists since Dolibarr 18 and uses
	 * $dolibarr_main_instance_unique_id from conf.php as key).
	 *
	 * @param  string $clear Clear secret
	 * @return string
	 */
	private static function encryptSecret($clear)
	{
		return function_exists('dolEncrypt') ? dolEncrypt($clear) : $clear;
	}

	/**
	 * @param  string $stored Stored secret
	 * @return string         Clear secret
	 */
	private static function decryptSecret($stored)
	{
		return function_exists('dolDecrypt') ? dolDecrypt($stored) : $stored;
	}

	/**
	 * Load the record of a user.
	 *
	 * @param  int $fk_user User id
	 * @return int          1 if found, 0 if not found, -1 if error
	 */
	public function fetchByUser($fk_user)
	{
		$sql = "SELECT rowid, fk_user, secret, status, backup_codes, last_timestep, fail_count,";
		$sql .= " date_lastfail, date_creation, date_activation, date_lastuse";
		$sql .= " FROM ".self::table()." WHERE fk_user = ".((int) $fk_user);
		$resql = $this->db->query($sql);
		if (!$resql) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		$obj = $this->db->fetch_object($resql);
		$this->db->free($resql);
		if (!$obj) {
			return 0;
		}
		$this->id = (int) $obj->rowid;
		$this->fk_user = (int) $obj->fk_user;
		$this->secret = self::decryptSecret($obj->secret);
		$this->status = (int) $obj->status;
		$codes = json_decode((string) $obj->backup_codes, true);
		$this->backup_codes = is_array($codes) ? $codes : array();
		$this->last_timestep = (int) $obj->last_timestep;
		$this->fail_count = (int) $obj->fail_count;
		$this->date_lastfail = $this->db->jdate($obj->date_lastfail);
		$this->date_creation = $this->db->jdate($obj->date_creation);
		$this->date_activation = $this->db->jdate($obj->date_activation);
		$this->date_lastuse = $this->db->jdate($obj->date_lastuse);
		return 1;
	}

	/**
	 * Tell if a user has an active TOTP.
	 *
	 * @param  DoliDB $db      Database handler
	 * @param  int    $fk_user User id
	 * @return bool
	 */
	public static function isActiveForUser($db, $fk_user)
	{
		$tmp = new self($db);
		return ($tmp->fetchByUser($fk_user) > 0 && $tmp->status == self::STATUS_ACTIVE);
	}

	/**
	 * Start (or restart) an enrollment: generate a new secret, status "enrolling".
	 * An already active TOTP is never overwritten here.
	 *
	 * @param  int $fk_user User id
	 * @return int          >0 if OK, <0 if KO
	 */
	public function startEnrollment($fk_user)
	{
		$res = $this->fetchByUser($fk_user);
		if ($res < 0) {
			return -1;
		}
		if ($res > 0 && $this->status == self::STATUS_ACTIVE) {
			$this->error = 'AlreadyActive';
			return -2;
		}
		$this->secret = TotpAuthTotp::generateSecret();
		$now = dol_now();
		if ($res > 0) {
			$sql = "UPDATE ".self::table()." SET secret = '".$this->db->escape(self::encryptSecret($this->secret))."',";
			$sql .= " status = ".self::STATUS_ENROLLING.", backup_codes = NULL, last_timestep = 0, fail_count = 0,";
			$sql .= " date_lastfail = NULL, date_creation = '".$this->db->idate($now)."', date_activation = NULL";
			$sql .= " WHERE rowid = ".((int) $this->id);
		} else {
			$sql = "INSERT INTO ".self::table()." (fk_user, secret, status, date_creation) VALUES (";
			$sql .= ((int) $fk_user).", '".$this->db->escape(self::encryptSecret($this->secret))."', ".self::STATUS_ENROLLING.", '".$this->db->idate($now)."')";
		}
		if (!$this->db->query($sql)) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		return $this->fetchByUser($fk_user);
	}

	/**
	 * Return true if verification is temporarily locked after too many failures.
	 *
	 * @return bool
	 */
	public function isLocked()
	{
		$max = max(1, getDolGlobalInt('TOTPAUTH_MAX_FAILS', 5));
		$lockseconds = 60 * max(1, getDolGlobalInt('TOTPAUTH_LOCK_MINUTES', 15));
		return ($this->fail_count >= $max && $this->date_lastfail && (dol_now() - $this->date_lastfail) < $lockseconds);
	}

	/**
	 * Verify a code (TOTP or recovery code) and update counters.
	 *
	 * @param  string $code        Code typed by user
	 * @param  bool   $allowBackup Accept recovery codes
	 * @return int                 VERIFY_OK, VERIFY_OK_BACKUP, VERIFY_BAD or VERIFY_LOCKED (-1 if SQL error)
	 */
	public function verifyCode($code, $allowBackup = true)
	{
		if (empty($this->id)) {
			return self::VERIFY_BAD;
		}
		if ($this->isLocked()) {
			return self::VERIFY_LOCKED;
		}

		$code = trim((string) $code);
		$step = TotpAuthTotp::verify($this->secret, $code, $this->last_timestep, 1);
		if ($step !== false) {
			$sql = "UPDATE ".self::table()." SET last_timestep = ".((int) $step).", fail_count = 0, date_lastfail = NULL,";
			$sql .= " date_lastuse = '".$this->db->idate(dol_now())."' WHERE rowid = ".((int) $this->id);
			// Condition on last_timestep: two concurrent requests with the same code cannot both succeed
			$sql .= " AND last_timestep < ".((int) $step);
			$resql = $this->db->query($sql);
			if (!$resql) {
				$this->error = $this->db->lasterror();
				return -1;
			}
			if ($this->db->affected_rows($resql) == 1) {
				$this->last_timestep = $step;
				$this->fail_count = 0;
				return self::VERIFY_OK;
			}
			return self::VERIFY_BAD;
		}

		if ($allowBackup && $this->status == self::STATUS_ACTIVE) {
			$normalized = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $code));
			if (strlen($normalized) == 10) {
				foreach ($this->backup_codes as $idx => $hash) {
					if (password_verify($normalized, $hash)) {
						unset($this->backup_codes[$idx]);
						$this->backup_codes = array_values($this->backup_codes);
						$sql = "UPDATE ".self::table()." SET backup_codes = '".$this->db->escape(json_encode($this->backup_codes))."',";
						$sql .= " fail_count = 0, date_lastfail = NULL, date_lastuse = '".$this->db->idate(dol_now())."'";
						$sql .= " WHERE rowid = ".((int) $this->id);
						if (!$this->db->query($sql)) {
							$this->error = $this->db->lasterror();
							return -1;
						}
						$this->fail_count = 0;
						return self::VERIFY_OK_BACKUP;
					}
				}
			}
		}

		// Failure: a lock that has expired restarts the counter
		$lockseconds = 60 * max(1, getDolGlobalInt('TOTPAUTH_LOCK_MINUTES', 15));
		$expired = ($this->date_lastfail && (dol_now() - $this->date_lastfail) >= $lockseconds);
		$this->fail_count = $expired ? 1 : $this->fail_count + 1;
		$this->date_lastfail = dol_now();
		$sql = "UPDATE ".self::table()." SET fail_count = ".((int) $this->fail_count).", date_lastfail = '".$this->db->idate($this->date_lastfail)."'";
		$sql .= " WHERE rowid = ".((int) $this->id);
		$this->db->query($sql);

		return $this->isLocked() ? self::VERIFY_LOCKED : self::VERIFY_BAD;
	}

	/**
	 * Activate the TOTP after a first valid code. Generates the recovery codes.
	 *
	 * @return string[]|int Clear recovery codes to show once to the user, or <0 if error
	 */
	public function activate()
	{
		$codes = $this->buildBackupCodes();
		$sql = "UPDATE ".self::table()." SET status = ".self::STATUS_ACTIVE.",";
		$sql .= " date_activation = '".$this->db->idate(dol_now())."',";
		$sql .= " backup_codes = '".$this->db->escape(json_encode($this->backup_codes))."'";
		$sql .= " WHERE rowid = ".((int) $this->id);
		if (!$this->db->query($sql)) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		$this->status = self::STATUS_ACTIVE;
		return $codes;
	}

	/**
	 * Replace the recovery codes by new ones.
	 *
	 * @return string[]|int Clear recovery codes, or <0 if error
	 */
	public function regenerateBackupCodes()
	{
		$codes = $this->buildBackupCodes();
		$sql = "UPDATE ".self::table()." SET backup_codes = '".$this->db->escape(json_encode($this->backup_codes))."'";
		$sql .= " WHERE rowid = ".((int) $this->id);
		if (!$this->db->query($sql)) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		return $codes;
	}

	/**
	 * Generate recovery codes, store their hashes in $this->backup_codes.
	 *
	 * @return string[] Clear codes formatted XXXXX-XXXXX
	 */
	private function buildBackupCodes()
	{
		$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No 0/O/1/I to avoid confusion
		$clear = array();
		$this->backup_codes = array();
		for ($i = 0; $i < self::NB_BACKUP_CODES; $i++) {
			$c = '';
			for ($j = 0; $j < 10; $j++) {
				$c .= $alphabet[random_int(0, strlen($alphabet) - 1)];
			}
			$clear[] = substr($c, 0, 5).'-'.substr($c, 5);
			$this->backup_codes[] = password_hash($c, PASSWORD_DEFAULT);
		}
		return $clear;
	}

	/**
	 * Remove the TOTP of the user (disable second factor).
	 *
	 * @return int >0 if OK, <0 if KO
	 */
	public function delete()
	{
		$sql = "DELETE FROM ".self::table()." WHERE rowid = ".((int) $this->id);
		if (!$this->db->query($sql)) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		$this->id = 0;
		return 1;
	}
}
