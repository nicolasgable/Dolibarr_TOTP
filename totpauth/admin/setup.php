<?php
/* Copyright (C) 2026 AllSafe
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * \file    totpauth/admin/setup.php
 * \ingroup totpauth
 * \brief   Setup page of module TotpAuth.
 */

// Load Dolibarr environment
$res = 0;
if (!$res && !empty($_SERVER["CONTEXT_DOCUMENT_ROOT"])) {
	$res = @include $_SERVER["CONTEXT_DOCUMENT_ROOT"]."/main.inc.php";
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

require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/security.lib.php';
dol_include_once('/totpauth/lib/totpauth.lib.php');

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var Translate $langs
 * @var User $user
 */

$langs->loadLangs(array('admin', 'totpauth@totpauth'));

if (empty($user->admin)) {
	accessforbidden();
}

$action = GETPOST('action', 'aZ09');

if ($action == 'save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
	$force = GETPOSTINT('TOTPAUTH_FORCE');
	$maxfails = max(1, GETPOSTINT('TOTPAUTH_MAX_FAILS'));
	$lockmin = max(1, GETPOSTINT('TOTPAUTH_LOCK_MINUTES'));
	$issuer = trim(GETPOST('TOTPAUTH_ISSUER', 'alphanohtml'));

	$error = 0;
	$error += (dolibarr_set_const($db, 'TOTPAUTH_FORCE', (string) (in_array($force, array(0, 1, 2)) ? $force : 0), 'chaine', 0, '', $conf->entity) < 0);
	$error += (dolibarr_set_const($db, 'TOTPAUTH_MAX_FAILS', (string) $maxfails, 'chaine', 0, '', $conf->entity) < 0);
	$error += (dolibarr_set_const($db, 'TOTPAUTH_LOCK_MINUTES', (string) $lockmin, 'chaine', 0, '', $conf->entity) < 0);
	$error += (dolibarr_set_const($db, 'TOTPAUTH_ISSUER', $issuer, 'chaine', 0, '', $conf->entity) < 0);

	if ($error) {
		setEventMessages($langs->trans('Error'), null, 'errors');
	} else {
		setEventMessages($langs->trans('SetupSaved'), null, 'mesgs');
	}
	header('Location: '.$_SERVER['PHP_SELF']);
	exit;
}


/*
 * View
 */

llxHeader('', $langs->trans('TotpSetup'), '', '', 0, 0, '', '', '', 'mod-totpauth page-admin');

$linkback = '<a href="'.DOL_URL_ROOT.'/admin/modules.php?restore_lastsearch_values=1">'.$langs->trans('BackToModuleList').'</a>';
print load_fiche_titre($langs->trans('TotpSetup'), $linkback, 'title_setup');

$head = totpauthAdminPrepareHead();
print dol_get_fiche_head($head, 'settings', '', -1, 'lock');

print '<span class="opacitymedium">'.$langs->trans('TotpSetupDesc').'</span><br><br>';

print '<form method="POST" action="'.$_SERVER['PHP_SELF'].'">';
print '<input type="hidden" name="token" value="'.newToken().'">';
print '<input type="hidden" name="action" value="save">';

print '<table class="noborder centpercent">';
print '<tr class="liste_titre"><td>'.$langs->trans('Parameter').'</td><td>'.$langs->trans('Value').'</td></tr>';

$force = getDolGlobalInt('TOTPAUTH_FORCE');
print '<tr class="oddeven"><td>'.$langs->trans('TotpForce').'<br><span class="opacitymedium small">'.$langs->trans('TotpForceHelp').'</span></td><td>';
print '<select name="TOTPAUTH_FORCE" class="flat minwidth200">';
foreach (array(0 => 'TotpForce0', 1 => 'TotpForce1', 2 => 'TotpForce2') as $k => $lab) {
	print '<option value="'.$k.'"'.($force == $k ? ' selected' : '').'>'.$langs->trans($lab).'</option>';
}
print '</select></td></tr>';

print '<tr class="oddeven"><td>'.$langs->trans('TotpIssuer').'<br><span class="opacitymedium small">'.$langs->trans('TotpIssuerHelp').'</span></td><td>';
print '<input type="text" class="flat minwidth200" name="TOTPAUTH_ISSUER" value="'.dol_escape_htmltag(getDolGlobalString('TOTPAUTH_ISSUER')).'" placeholder="'.dol_escape_htmltag(getDolGlobalString('MAIN_INFO_SOCIETE_NOM', 'Dolibarr')).'"></td></tr>';

print '<tr class="oddeven"><td>'.$langs->trans('TotpMaxFails').'</td><td>';
print '<input type="number" min="1" max="50" class="flat width75" name="TOTPAUTH_MAX_FAILS" value="'.getDolGlobalInt('TOTPAUTH_MAX_FAILS', 5).'"></td></tr>';

print '<tr class="oddeven"><td>'.$langs->trans('TotpLockMinutes').'</td><td>';
print '<input type="number" min="1" max="1440" class="flat width75" name="TOTPAUTH_LOCK_MINUTES" value="'.getDolGlobalInt('TOTPAUTH_LOCK_MINUTES', 15).'"></td></tr>';

print '</table>';
print '<div class="center"><input type="submit" class="button button-save" value="'.dol_escape_htmltag($langs->trans('Save')).'"></div>';
print '</form>';

if (!function_exists('dolEncrypt')) {
	print '<br><div class="warning">'.$langs->trans('TotpNoEncryption').'</div>';
}

print dol_get_fiche_end();

llxFooter();
$db->close();
