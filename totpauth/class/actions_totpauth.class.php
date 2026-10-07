<?php
/* Copyright (C) 2026 AllSafe
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * \file    totpauth/class/actions_totpauth.class.php
 * \ingroup totpauth
 * \brief   Hooks that put the TOTP challenge between password login and the application.
 *
 * How it works:
 *  - hook "afterLogin" (context "login"): the password was just accepted. If the user has an active TOTP
 *    (or must enroll one), we flag the session as "pending" and redirect to verify.php immediately,
 *    so the page requested with the login form is never rendered.
 *  - hook "updateSession" (context "main"): called on every request of an already authenticated session.
 *    While the session is "pending", every page except verify.php and logout.php is redirected
 *    (or gets HTTP 401 for ajax/non html calls).
 */

class ActionsTotpauth
{
	/** @var DoliDB */
	public $db;
	public $error = '';
	public $errors = array();
	public $results = array();
	public $resprints = '';

	/**
	 * @param DoliDB $db Database handler
	 */
	public function __construct($db)
	{
		$this->db = $db;
	}

	/**
	 * Hook afterLogin.
	 *
	 * @param  array<string,mixed> $parameters Hook parameters
	 * @param  User                $object     Logged user
	 * @param  string              $action     Action
	 * @param  HookManager         $hookmanager Hook manager
	 * @return int
	 */
	public function afterLogin($parameters, &$object, &$action, $hookmanager)
	{
		$u = $object;
		if (!is_object($u) || empty($u->id)) {
			return 0;
		}

		dol_include_once('/totpauth/class/totpauthuser.class.php');
		dol_include_once('/totpauth/lib/totpauth.lib.php');

		$mode = '';
		if (TotpAuthUser::isActiveForUser($this->db, $u->id)) {
			$mode = 'verify';
		} elseif (totpauth_is_mandatory($u)) {
			$mode = 'enroll';
		}
		if ($mode === '') {
			return 0;
		}

		$_SESSION['totpauth_pending'] = $mode;
		$_SESSION['totpauth_fails'] = 0;
		// Page the user wanted, restored after the challenge (only for GET, the login POST has no value to replay)
		$_SESSION['totpauth_backurl'] = totpauth_safe_backurl($_SERVER['REQUEST_METHOD'] === 'GET' ? ($_SERVER['REQUEST_URI'] ?? '') : (string) ($_SERVER['PHP_SELF'] ?? ''));

		dol_syslog('totpauth: password accepted for '.$u->login.', second factor required (mode='.$mode.')', LOG_NOTICE);

		// main.inc.php opened a transaction for USER_LOGIN trigger / last login date. Commit it before leaving,
		// so the security event log is kept, then stop the request before any page is rendered.
		$this->db->commit();
		header('Location: '.dol_buildpath('/totpauth/verify.php', 1));
		exit;
	}

	/**
	 * Hook updateSession: block every page while the second factor is not validated.
	 *
	 * @param  array<string,mixed> $parameters  Hook parameters
	 * @param  User                $object      Logged user
	 * @param  string              $action      Action
	 * @param  HookManager         $hookmanager Hook manager
	 * @return int
	 */
	public function updateSession($parameters, &$object, &$action, $hookmanager)
	{
		if (empty($_SESSION['totpauth_pending'])) {
			return 0;
		}
		// The challenge page itself
		if (defined('TOTPAUTH_CHALLENGE_PAGE')) {
			return 0;
		}
		// Allow logout
		$self = (string) ($_SERVER['PHP_SELF'] ?? '');
		if (preg_match('/\/user\/logout\.php$/', $self)) {
			return 0;
		}

		$isAjax = (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest')
			|| defined('NOREQUIREHTML') || strpos($self, '/ajax/') !== false;

		if ($isAjax) {
			http_response_code(401);
			header('Content-Type: text/plain; charset=utf-8');
			print 'Second authentication factor required';
			exit;
		}
		header('Location: '.dol_buildpath('/totpauth/verify.php', 1));
		exit;
	}
}
