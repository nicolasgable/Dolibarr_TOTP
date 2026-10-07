<?php
/* Copyright (C) 2026 AllSafe
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * \file    totpauth/user_totp.php
 * \ingroup totpauth
 * \brief   Tab "Double authentification" on the user card: enroll, disable, recovery codes, admin reset.
 */

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

require_once DOL_DOCUMENT_ROOT.'/user/class/user.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/usergroups.lib.php';
dol_include_once('/totpauth/class/totpauthuser.class.php');
dol_include_once('/totpauth/lib/totpauth.lib.php');

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var Translate $langs
 * @var User $user
 */

$langs->loadLangs(array('users', 'admin', 'totpauth@totpauth'));

$id = GETPOSTINT('id');
if ($id <= 0) {
	$id = $user->id;
}
$action = GETPOST('action', 'aZ09');

if (!isModEnabled('totpauth')) {
	accessforbidden('Module not enabled');
}

$object = new User($db);
if ($object->fetch($id) <= 0) {
	accessforbidden();
}

$isSelf = ($object->id == $user->id);
$canManage = (!empty($user->admin) || $user->hasRight('totpauth', 'manage'));
if (!$isSelf && !$canManage) {
	accessforbidden();
}
// A non superadmin cannot reset the second factor of a superadmin
if (!$isSelf && !empty($object->admin) && empty($user->admin)) {
	accessforbidden();
}

$rec = new TotpAuthUser($db);
$res = $rec->fetchByUser($object->id);
if ($res < 0) {
	dol_print_error($db, $rec->error);
	exit;
}
$mandatory = totpauth_is_mandatory($object);

$codesToShow = null;

/*
 * Actions
 */

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action) {
	$code = GETPOST('code', 'alphanohtml');

	if ($isSelf && $action == 'start') {
		if ($rec->startEnrollment($object->id) < 0 && $rec->error != 'AlreadyActive') {
			setEventMessages($rec->error, null, 'errors');
		}
	} elseif ($isSelf && $action == 'cancel' && $res > 0 && $rec->status == TotpAuthUser::STATUS_ENROLLING) {
		$rec->delete();
	} elseif ($isSelf && $action == 'confirm' && $res > 0 && $rec->status == TotpAuthUser::STATUS_ENROLLING) {
		$r = $rec->verifyCode($code, false);
		if ($r == TotpAuthUser::VERIFY_OK) {
			$codesToShow = $rec->activate();
			if (is_array($codesToShow)) {
				$_SESSION['totpauth_validated'] = dol_now();
				dol_syslog('totpauth: second factor enrolled for '.$object->login, LOG_NOTICE);
				setEventMessages($langs->trans('TotpEnabledOk'), null, 'mesgs');
			} else {
				setEventMessages($rec->error, null, 'errors');
			}
		} elseif ($r == TotpAuthUser::VERIFY_LOCKED) {
			setEventMessages($langs->trans('TotpLocked', getDolGlobalInt('TOTPAUTH_LOCK_MINUTES', 15)), null, 'errors');
		} else {
			setEventMessages($langs->trans('TotpErrorBadCode'), null, 'errors');
		}
	} elseif ($isSelf && in_array($action, array('disable', 'regencodes')) && $res > 0 && $rec->status == TotpAuthUser::STATUS_ACTIVE) {
		// Sensitive operations on own account need a valid current code (TOTP only, not a recovery code)
		$r = $rec->verifyCode($code, false);
		if ($r == TotpAuthUser::VERIFY_OK) {
			if ($action == 'disable') {
				if ($mandatory) {
					setEventMessages($langs->trans('TotpCannotDisableMandatory'), null, 'errors');
				} else {
					$rec->delete();
					dol_syslog('totpauth: second factor disabled by '.$user->login.' for himself', LOG_NOTICE);
					setEventMessages($langs->trans('TotpDisabledOk'), null, 'mesgs');
				}
			} else {
				$codesToShow = $rec->regenerateBackupCodes();
				if (!is_array($codesToShow)) {
					setEventMessages($rec->error, null, 'errors');
					$codesToShow = null;
				}
			}
		} elseif ($r == TotpAuthUser::VERIFY_LOCKED) {
			setEventMessages($langs->trans('TotpLocked', getDolGlobalInt('TOTPAUTH_LOCK_MINUTES', 15)), null, 'errors');
		} else {
			setEventMessages($langs->trans('TotpErrorBadCode'), null, 'errors');
		}
	} elseif (!$isSelf && $canManage && $action == 'reset' && $res > 0) {
		$rec->delete();
		dol_syslog('totpauth: second factor of '.$object->login.' reset by '.$user->login, LOG_NOTICE);
		setEventMessages($langs->trans('TotpResetOk', $object->login), null, 'mesgs');
	}

	if ($codesToShow === null) {
		// Post/Redirect/Get
		header('Location: '.$_SERVER['PHP_SELF'].'?id='.$object->id);
		exit;
	}
	$res = $rec->fetchByUser($object->id);
}


/*
 * View
 */

$title = $object->getFullName($langs).' - '.$langs->trans('TotpTabTitle');
llxHeader('', $title, '', '', 0, 0, '', '', '', 'mod-totpauth page-user');

$head = user_prepare_head($object);
print dol_get_fiche_head($head, 'totpauth', $langs->trans('User'), -1, 'user');

$linkback = '';
if ($user->hasRight('user', 'user', 'lire') || $user->admin) {
	$linkback = '<a href="'.DOL_URL_ROOT.'/user/list.php?restore_lastsearch_values=1">'.$langs->trans('BackToList').'</a>';
}
dol_banner_tab($object, 'id', $linkback, $user->hasRight('user', 'user', 'lire') || $user->admin);

print '<div class="fichecenter"><div class="underbanner clearboth"></div>';

// Status table
print '<table class="border centpercent tableforfield">';
print '<tr><td class="titlefield">'.$langs->trans('Status').'</td><td>';
if ($res > 0 && $rec->status == TotpAuthUser::STATUS_ACTIVE) {
	print dolGetStatus($langs->trans('TotpStatusActive'), '', '', 'status4', 1);
} elseif ($res > 0) {
	print dolGetStatus($langs->trans('TotpStatusEnrolling'), '', '', 'status1', 1);
} else {
	print dolGetStatus($langs->trans('TotpStatusNone'), '', '', 'status0', 1);
}
if ($mandatory) {
	print ' &nbsp; <span class="badge badge-warning">'.$langs->trans('TotpMandatoryForThisUser').'</span>';
}
print '</td></tr>';
if ($res > 0 && $rec->status == TotpAuthUser::STATUS_ACTIVE) {
	print '<tr><td>'.$langs->trans('TotpActivatedOn').'</td><td>'.dol_print_date($rec->date_activation, 'dayhour', 'tzuserrel').'</td></tr>';
	print '<tr><td>'.$langs->trans('TotpLastUse').'</td><td>'.($rec->date_lastuse ? dol_print_date($rec->date_lastuse, 'dayhour', 'tzuserrel') : '-').'</td></tr>';
	print '<tr><td>'.$langs->trans('TotpBackupCodesLeft').'</td><td>'.count($rec->backup_codes).' / '.TotpAuthUser::NB_BACKUP_CODES.'</td></tr>';
	if ($rec->isLocked()) {
		print '<tr><td>'.$langs->trans('TotpLockedTitle').'</td><td><span class="error">'.$langs->trans('Yes').'</span></td></tr>';
	}
}
print '</table>';
print '</div>';

print dol_get_fiche_end();

$tokenfield = '<input type="hidden" name="token" value="'.newToken().'"><input type="hidden" name="id" value="'.$object->id.'">';
$codeinput = '<input type="text" name="code" class="maxwidth100" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" autocomplete="one-time-code" placeholder="123456" required>';

if (is_array($codesToShow)) {
	print '<br><div class="info">'.totpauth_print_backup_codes($codesToShow, $langs).'</div>';
	print '<div class="center"><a class="button" href="'.$_SERVER['PHP_SELF'].'?id='.$object->id.'">'.$langs->trans('TotpContinue').'</a></div>';
} elseif ($isSelf) {
	if ($res == 0) {
		print '<br><p>'.$langs->trans('TotpIntro').'</p>';
		print '<form method="POST" action="'.$_SERVER['PHP_SELF'].'">'.$tokenfield.'<input type="hidden" name="action" value="start">';
		print '<input type="submit" class="button" value="'.dol_escape_htmltag($langs->trans('TotpEnable')).'"></form>';
	} elseif ($rec->status == TotpAuthUser::STATUS_ENROLLING) {
		$uri = TotpAuthTotp::provisioningUri($rec->secret, $object->login, totpauth_issuer());
		print '<br><div class="center">';
		print '<ol style="display:inline-block;text-align:left"><li>'.$langs->trans('TotpEnrollStep1').'</li><li>'.$langs->trans('TotpEnrollStep2').'</li><li>'.$langs->trans('TotpEnrollStep3').'</li></ol><br>';
		print totpauth_qr_svg($uri);
		print '<p>'.$langs->trans('TotpManualKey').'<br><code style="font-size:1.15em;user-select:all">'.dol_escape_htmltag(totpauth_format_secret($rec->secret)).'</code></p>';
		print '<form method="POST" action="'.$_SERVER['PHP_SELF'].'">'.$tokenfield.'<input type="hidden" name="action" value="confirm">';
		print $codeinput.' <input type="submit" class="button" value="'.dol_escape_htmltag($langs->trans('TotpValidate')).'"></form>';
		print '<form method="POST" action="'.$_SERVER['PHP_SELF'].'" style="margin-top:10px">'.$tokenfield.'<input type="hidden" name="action" value="cancel">';
		print '<input type="submit" class="button button-cancel" value="'.dol_escape_htmltag($langs->trans('Cancel')).'"></form>';
		print '</div>';
	} else {
		print '<br><table class="noborder centpercent">';
		print '<tr class="liste_titre"><td colspan="2">'.$langs->trans('TotpManage').'</td></tr>';

		print '<tr class="oddeven"><td>'.$langs->trans('TotpRegenCodes').'<br><span class="opacitymedium">'.$langs->trans('TotpNeedCurrentCode').'</span></td><td class="right">';
		print '<form method="POST" action="'.$_SERVER['PHP_SELF'].'">'.$tokenfield.'<input type="hidden" name="action" value="regencodes">';
		print $codeinput.' <input type="submit" class="button smallpaddingimp" value="'.dol_escape_htmltag($langs->trans('TotpRegenerate')).'"></form></td></tr>';

		print '<tr class="oddeven"><td>'.$langs->trans('TotpDisable').'<br><span class="opacitymedium">'.($mandatory ? $langs->trans('TotpCannotDisableMandatory') : $langs->trans('TotpNeedCurrentCode')).'</span></td><td class="right">';
		if (!$mandatory) {
			print '<form method="POST" action="'.$_SERVER['PHP_SELF'].'" onsubmit="return confirm(\''.dol_escape_js($langs->transnoentitiesnoconv('TotpConfirmDisable')).'\');">'.$tokenfield.'<input type="hidden" name="action" value="disable">';
			print $codeinput.' <input type="submit" class="button button-delete smallpaddingimp" value="'.dol_escape_htmltag($langs->trans('TotpDisableButton')).'"></form>';
		}
		print '</td></tr></table>';
	}
} elseif ($canManage && $res > 0) {
	print '<br><div class="tabsAction">';
	print '<form method="POST" action="'.$_SERVER['PHP_SELF'].'" style="display:inline" onsubmit="return confirm(\''.dol_escape_js($langs->transnoentitiesnoconv('TotpConfirmReset', $object->login)).'\');">'.$tokenfield.'<input type="hidden" name="action" value="reset">';
	print '<input type="submit" class="butActionDelete" value="'.dol_escape_htmltag($langs->trans('TotpResetButton')).'"></form>';
	print '</div>';
	print '<p class="opacitymedium">'.$langs->trans('TotpResetHelp').'</p>';
}

llxFooter();
$db->close();
