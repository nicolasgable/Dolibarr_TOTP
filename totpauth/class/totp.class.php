<?php
/* Copyright (C) 2026 AllSafe
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * \file    totpauth/class/totp.class.php
 * \ingroup totpauth
 * \brief   Pure PHP implementation of TOTP (RFC 6238) / HOTP (RFC 4226) and Base32 (RFC 4648).
 *          No dependency on Dolibarr, so it can be unit tested alone.
 */

class TotpAuthTotp
{
	const PERIOD = 30;
	const DIGITS = 6;
	const ALGO   = 'sha1';

	const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generate a random Base32 secret.
	 *
	 * @param  int    $bytes  Number of random bytes (20 = 160 bits, recommended by RFC 4226)
	 * @return string         Base32 secret without padding
	 */
	public static function generateSecret($bytes = 20)
	{
		return self::base32Encode(random_bytes($bytes));
	}

	/**
	 * Base32 encode (RFC 4648), without padding.
	 *
	 * @param  string $data Binary data
	 * @return string
	 */
	public static function base32Encode($data)
	{
		$out = '';
		$buffer = 0;
		$bits = 0;
		$len = strlen($data);
		for ($i = 0; $i < $len; $i++) {
			$buffer = ($buffer << 8) | ord($data[$i]);
			$bits += 8;
			while ($bits >= 5) {
				$bits -= 5;
				$out .= self::BASE32_ALPHABET[($buffer >> $bits) & 31];
			}
		}
		if ($bits > 0) {
			$out .= self::BASE32_ALPHABET[($buffer << (5 - $bits)) & 31];
		}
		return $out;
	}

	/**
	 * Base32 decode (RFC 4648). Tolerates lower case, spaces and padding.
	 *
	 * @param  string       $b32 Base32 string
	 * @return string|false      Binary data, or false if invalid
	 */
	public static function base32Decode($b32)
	{
		$b32 = strtoupper(preg_replace('/[\s=]/', '', (string) $b32));
		if ($b32 === '' || preg_match('/[^A-Z2-7]/', $b32)) {
			return false;
		}
		$out = '';
		$buffer = 0;
		$bits = 0;
		$len = strlen($b32);
		for ($i = 0; $i < $len; $i++) {
			$buffer = (($buffer << 5) | strpos(self::BASE32_ALPHABET, $b32[$i])) & 0xFFFFFF;
			$bits += 5;
			if ($bits >= 8) {
				$bits -= 8;
				$out .= chr(($buffer >> $bits) & 0xFF);
			}
		}
		return $out;
	}

	/**
	 * Compute a HOTP value (RFC 4226).
	 *
	 * @param  string $key     Binary key
	 * @param  int    $counter Counter (time step for TOTP)
	 * @param  int    $digits  Number of digits
	 * @param  string $algo    sha1|sha256|sha512
	 * @return string          Zero padded code
	 */
	public static function hotp($key, $counter, $digits = self::DIGITS, $algo = self::ALGO)
	{
		// 8-byte big endian counter (pack 'J' needs 64 bits PHP, which is the norm today)
		$msg = pack('N2', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
		$hash = hash_hmac($algo, $msg, $key, true);
		$offset = ord($hash[strlen($hash) - 1]) & 0x0F;
		$bin = ((ord($hash[$offset]) & 0x7F) << 24)
			| ((ord($hash[$offset + 1]) & 0xFF) << 16)
			| ((ord($hash[$offset + 2]) & 0xFF) << 8)
			| (ord($hash[$offset + 3]) & 0xFF);
		return str_pad((string) ($bin % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
	}

	/**
	 * Return the time step for a timestamp.
	 *
	 * @param  int|null $time Unix timestamp (null = now)
	 * @return int
	 */
	public static function timeStep($time = null)
	{
		return (int) floor(($time === null ? time() : $time) / self::PERIOD);
	}

	/**
	 * Compute the TOTP code for a Base32 secret at a given time.
	 *
	 * @param  string   $secretB32 Base32 secret
	 * @param  int|null $time      Unix timestamp (null = now)
	 * @return string|false
	 */
	public static function code($secretB32, $time = null)
	{
		$key = self::base32Decode($secretB32);
		if ($key === false) {
			return false;
		}
		return self::hotp($key, self::timeStep($time));
	}

	/**
	 * Verify a TOTP code with a tolerance window, with anti-replay protection.
	 *
	 * @param  string   $secretB32    Base32 secret
	 * @param  string   $code         Code typed by user
	 * @param  int      $lastTimeStep Last time step already accepted for this secret (0 if none). Codes at or before this step are refused.
	 * @param  int      $window       Number of steps accepted before/after current step (1 = +/- 30 s)
	 * @param  int|null $time         Unix timestamp (null = now)
	 * @return int|false              Matching time step if valid, false otherwise
	 */
	public static function verify($secretB32, $code, $lastTimeStep = 0, $window = 1, $time = null)
	{
		$code = preg_replace('/\s+/', '', (string) $code);
		if (!preg_match('/^\d{'.self::DIGITS.'}$/', $code)) {
			return false;
		}
		$key = self::base32Decode($secretB32);
		if ($key === false) {
			return false;
		}
		$current = self::timeStep($time);
		$found = false;
		// Loop on the whole window, without early exit, to keep a constant time
		for ($i = -$window; $i <= $window; $i++) {
			$step = $current + $i;
			if (hash_equals(self::hotp($key, $step), $code) && $step > (int) $lastTimeStep && $found === false) {
				$found = $step;
			}
		}
		return $found;
	}

	/**
	 * Build the otpauth:// URI used by authenticator apps (Key Uri Format).
	 *
	 * @param  string $secretB32 Base32 secret
	 * @param  string $account   Account name (user login)
	 * @param  string $issuer    Issuer (company / application name)
	 * @return string
	 */
	public static function provisioningUri($secretB32, $account, $issuer)
	{
		$issuer = str_replace(':', '', (string) $issuer);
		$label = rawurlencode($issuer).':'.rawurlencode(str_replace(':', '', (string) $account));
		return 'otpauth://totp/'.$label.'?secret='.$secretB32
			.'&issuer='.rawurlencode($issuer)
			.'&algorithm='.strtoupper(self::ALGO).'&digits='.self::DIGITS.'&period='.self::PERIOD;
	}
}
