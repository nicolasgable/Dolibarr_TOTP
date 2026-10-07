<?php
/* Copyright (C) 2026 AllSafe
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * \file    totpauth/verify.php
 * \ingroup totpauth
 * \brief   Second factor challenge shown right after password login
 *          (code verification, or forced enrollment when the second factor is mandatory).
 */

// Tell the updateSession hook that this page is allowed while the session is "pending"
if (!defined('TOTPAUTH_CHALLENGE_PAGE')) {
	define('TOTPAUTH_CHALLENGE_PAGE', 1);
}
if (!defined('NOREQUIREMENU')) {
	define('NOREQUIREMENU', 1);
}

// Load Dolibarr environment
$res = 0;
if (!$res && !empty($_SERVER["CONTEXT_DOCUMENT_ROOT"])) {
	$res = @include $_SERVER["CONTEXT_DOCUMENT_ROOT"]."/main.inc.php";
}
if (!$res && file_exists("../main.inc.php")) {
	$res = @include "../main.inc.php";
}
if (!$res && file_exists("../../main.inc.php")) {
	$res = @include "../../main.inc.php";
}
if (!$res && file_exists("../../../main.inc.php")) {
	$res = @include "../../../main.inc.php";
}
if (!$res) {
	die("Include of main fails");
}

dol_include_once('/totpauth/class/totpauthuser.class.php');
dol_include_once('/totpauth/lib/totpauth.lib.php');

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var Translate $langs
 * @var User $user
 */

$langs->loadLangs(array('main', 'totpauth@totpauth'));

$action = GETPOST('action', 'aZ09');
$mode = isset($_SESSION['totpauth_pending']) ? (string) $_SESSION['totpauth_pending'] : '';
$backurl = totpauth_safe_backurl(isset($_SESSION['totpauth_backurl']) ? $_SESSION['totpauth_backurl'] : '');

if ($mode === '') {
	// Nothing to do here (already validated, or second factor not required)
	header('Location: '.$backurl);
	exit;
}

$rec = new TotpAuthUser($db);
$res = $rec->fetchByUser($user->id);
if ($res < 0) {
	dol_print_error($db, $rec->error);
	exit;
}

// Consistency: the TOTP may have been removed/activated by an admin in the meantime
if ($mode === 'verify' && ($res == 0 || $rec->status != TotpAuthUser::STATUS_ACTIVE)) {
	$mode = totpauth_is_mandatory($user) ? 'enroll' : '';
}
if ($mode === 'enroll' && $res > 0 && $rec->status == TotpAuthUser::STATUS_ACTIVE) {
	$mode = 'verify';
}
if ($mode === '') {
	unset($_SESSION['totpauth_pending']);
	header('Location: '.$backurl);
	exit;
}
$_SESSION['totpauth_pending'] = $mode;

if ($mode === 'enroll' && ($res == 0 || $rec->status != TotpAuthUser::STATUS_ENROLLING)) {
	if ($rec->startEnrollment($user->id) < 0) {
		dol_print_error($db, $rec->error);
		exit;
	}
}

/**
 * Mark the second factor as validated for this session.
 *
 * @return void
 */
function totpauth_session_validated()
{
	unset($_SESSION['totpauth_pending'], $_SESSION['totpauth_fails'], $_SESSION['totpauth_backurl']);
	$_SESSION['totpauth_validated'] = dol_now();
	// New session id once fully authenticated (session fixation protection)
	@session_regenerate_id(true);
}

$errormsg = '';
$locked = false;
$codesToShow = null;

/*
 * Actions
 */

if ($action == 'verify' && $_SERVER['REQUEST_METHOD'] === 'POST') {
	$code = GETPOST('code', 'alphanohtml');
	$result = $rec->verifyCode($code, ($mode === 'verify'));

	if ($result == TotpAuthUser::VERIFY_OK || $result == TotpAuthUser::VERIFY_OK_BACKUP) {
		if ($mode === 'enroll') {
			$codesToShow = $rec->activate();
			if (!is_array($codesToShow)) {
				dol_print_error($db, $rec->error);
				exit;
			}
			dol_syslog('totpauth: second factor enrolled for '.$user->login, LOG_NOTICE);
			totpauth_session_validated();
			// Fall through to the view, that shows the recovery codes once
		} else {
			dol_syslog('totpauth: second factor validated for '.$user->login.($result == TotpAuthUser::VERIFY_OK_BACKUP ? ' (recovery code)' : ''), LOG_NOTICE);
			totpauth_session_validated();
			if ($result == TotpAuthUser::VERIFY_OK_BACKUP) {
				setEventMessages($langs->trans('TotpBackupCodeUsed', count($rec->backup_codes)), null, count($rec->backup_codes) <= 2 ? 'warnings' : 'mesgs');
			}
			header('Location: '.$backurl);
			exit;
		}
	} elseif ($result == TotpAuthUser::VERIFY_LOCKED) {
		$locked = true;
	} else {
		$_SESSION['totpauth_fails'] = (int) ($_SESSION['totpauth_fails'] ?? 0) + 1;
		dol_syslog('totpauth: wrong second factor for '.$user->login.' from '.getUserRemoteIP(), LOG_WARNING);
		$errormsg = $langs->trans('TotpErrorBadCode');
	}
} elseif ($rec->isLocked()) {
	$locked = true;
}

if ($locked) {
	dol_syslog('totpauth: second factor locked for '.$user->login.' from '.getUserRemoteIP(), LOG_WARNING);
	// Kill the half authenticated session
	$_SESSION = array();
	@session_destroy();
}


/*
 * View
 */

top_htmlhead('', $langs->trans('TotpTitle'), 0, 0, array(), array(), 1);

$logouturl = DOL_URL_ROOT.'/user/logout.php?token='.newToken();
?>
<body class="body bodylogin">
<style>
	.totpauth-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px; box-sizing: border-box; }
	.totpauth-card { background: var(--colorbackbody, #fff); color: var(--colortext, #222); max-width: 460px; width: 100%; padding: 28px 28px 22px; border-radius: 10px; box-shadow: 0 6px 30px rgba(0,0,0,.15); text-align: center; }
	.totpauth-card h1 { font-size: 1.35em; margin: 0 0 6px; }
	.totpauth-card .totpauth-sub { opacity: .75; margin-bottom: 18px; }
	.totpauth-card input.totpauth-code { font-size: 1.6em; letter-spacing: .25em; text-align: center; width: 100%; max-width: 260px; padding: 8px; box-sizing: border-box; }
	.totpauth-card .totpauth-err { color: #b00020; margin: 10px 0; font-weight: bold; }
	.totpauth-card .totpauth-secret { font-family: monospace; font-size: 1.1em; word-break: break-all; user-select: all; }
	.totpauth-card .totpauth-links { margin-top: 18px; font-size: .9em; }
	.totpauth-card ol { text-align: left; padding-left: 20px; }
</style>
<div class="totpauth-wrap"><div class="totpauth-card">
<?php

if ($locked) {
	print '<h1>'.$langs->trans('TotpLockedTitle').'</h1>';
	print '<p>'.$langs->trans('TotpLocked', getDolGlobalInt('TOTPAUTH_LOCK_MINUTES', 15)).'</p>';
	print '<div class="totpauth-links"><a class="button" href="'.DOL_URL_ROOT.'/index.php">'.$langs->trans('TotpBackToLogin').'</a></div>';
} elseif (is_array($codesToShow)) {
	print '<h1>'.$langs->trans('TotpEnrolledTitle').'</h1>';
	print totpauth_print_backup_codes($codesToShow, $langs);
	print '<div class="totpauth-links"><a class="button" href="'.dol_escape_htmltag($backurl).'">'.$langs->trans('TotpContinue').'</a></div>';
} else {
	print '<h1>'.$langs->trans($mode === 'enroll' ? 'TotpEnrollTitle' : 'TotpTitle').'</h1>';
	print '<div class="totpauth-sub">'.dol_escape_htmltag($user->getFullName($langs)).' ('.dol_escape_htmltag($user->login).')</div>';

	if ($mode === 'enroll') {
		$uri = TotpAuthTotp::provisioningUri($rec->secret, $user->login, totpauth_issuer());
		print '<p>'.$langs->trans('TotpEnrollMandatory').'</p>';
		print '<ol><li>'.$langs->trans('TotpEnrollStep1').'</li><li>'.$langs->trans('TotpEnrollStep2').'</li><li>'.$langs->trans('TotpEnrollStep3').'</li></ol>';
		print totpauth_qr_svg($uri);
		print '<p>'.$langs->trans('TotpManualKey').'<br><span class="totpauth-secret">'.dol_escape_htmltag(totpauth_format_secret($rec->secret)).'</span></p>';
	} else {
		print '<p>'.$langs->trans('TotpEnterCode').'</p>';
	}

	if ($errormsg) {
		print '<div class="totpauth-err">'.dol_escape_htmltag($errormsg).'</div>';
	}

	print '<form method="POST" action="'.dol_escape_htmltag($_SERVER['PHP_SELF']).'" autocomplete="off">';
	print '<input type="hidden" name="token" value="'.newToken().'">';
	print '<input type="hidden" name="action" value="verify">';
	print '<input class="totpauth-code" type="text" name="code" '.($mode === 'enroll' ? 'inputmode="numeric" pattern="[0-9 ]*" maxlength="7"' : 'maxlength="11"');
	print ' autocomplete="one-time-code" autofocus required placeholder="123456">';
	print '<br><br><input type="submit" class="button" value="'.dol_escape_htmltag($langs->trans('TotpValidate')).'">';
	print '</form>';

	if ($mode === 'verify') {
		print '<p class="opacitymedium" style="font-size:.9em">'.$langs->trans('TotpBackupHint').'</p>';
	}
	print '<div class="totpauth-links"><a href="'.$logouturl.'">'.$langs->trans('Logout').'</a></div>';
}
?>
</div></div>
</body>
</html>
<?php
$db->close();
