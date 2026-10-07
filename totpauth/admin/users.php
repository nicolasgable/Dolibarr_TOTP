<?php
/* Copyright (C) 2026 AllSafe
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * \file    totpauth/admin/users.php
 * \ingroup totpauth
 * \brief   Overview of second factor status for all active users.
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

require_once DOL_DOCUMENT_ROOT.'/user/class/user.class.php';
dol_include_once('/totpauth/class/totpauthuser.class.php');
dol_include_once('/totpauth/lib/totpauth.lib.php');

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var Translate $langs
 * @var User $user
 */

$langs->loadLangs(array('admin', 'users', 'totpauth@totpauth'));

if (empty($user->admin) && !$user->hasRight('totpauth', 'manage')) {
	accessforbidden();
}

llxHeader('', $langs->trans('TotpUsersStatus'), '', '', 0, 0, '', '', '', 'mod-totpauth page-admin-users');

$linkback = '<a href="'.DOL_URL_ROOT.'/admin/modules.php?restore_lastsearch_values=1">'.$langs->trans('BackToModuleList').'</a>';
print load_fiche_titre($langs->trans('TotpSetup'), $linkback, 'title_setup');

$head = totpauthAdminPrepareHead();
print dol_get_fiche_head($head, 'users', '', -1, 'lock');

$sql = "SELECT u.rowid, u.login, u.lastname, u.firstname, u.admin, u.entity,";
$sql .= " t.status as totp_status, t.date_activation, t.date_lastuse, t.fail_count";
$sql .= " FROM ".MAIN_DB_PREFIX."user as u";
$sql .= " LEFT JOIN ".MAIN_DB_PREFIX."totpauth_user as t ON t.fk_user = u.rowid";
$sql .= " WHERE u.statut = 1";
if (isModEnabled('multicompany') && !empty($user->entity)) {
	$sql .= " AND u.entity IN (0, ".((int) $conf->entity).")";
}
$sql .= " ORDER BY u.login ASC";

$resql = $db->query($sql);
if (!$resql) {
	dol_print_error($db);
	llxFooter();
	exit;
}

$nb = 0;
$nbactive = 0;
$nbmissing = 0;
$rows = array();
while ($obj = $db->fetch_object($resql)) {
	$rows[] = $obj;
}
$db->free($resql);

print '<table class="noborder centpercent">';
print '<tr class="liste_titre"><td>'.$langs->trans('Login').'</td><td>'.$langs->trans('Name').'</td><td class="center">'.$langs->trans('Administrator').'</td>';
print '<td class="center">'.$langs->trans('TotpTabTitle').'</td><td class="center">'.$langs->trans('TotpActivatedOn').'</td><td class="center">'.$langs->trans('TotpLastUse').'</td></tr>';

$tmpuser = new User($db);
foreach ($rows as $obj) {
	$nb++;
	$tmpuser->admin = $obj->admin;
	$mandatory = totpauth_is_mandatory($tmpuser);
	print '<tr class="oddeven">';
	print '<td><a href="'.dol_buildpath('/totpauth/user_totp.php', 1).'?id='.((int) $obj->rowid).'">'.img_picto('', 'user', 'class="pictofixedwidth"').dol_escape_htmltag($obj->login).'</a></td>';
	print '<td>'.dol_escape_htmltag(trim($obj->firstname.' '.$obj->lastname)).'</td>';
	print '<td class="center">'.($obj->admin ? yn(1) : '').'</td>';
	print '<td class="center">';
	if ($obj->totp_status !== null && (int) $obj->totp_status == TotpAuthUser::STATUS_ACTIVE) {
		$nbactive++;
		print dolGetStatus($langs->trans('TotpStatusActive'), '', '', 'status4', 1);
	} elseif ($obj->totp_status !== null) {
		print dolGetStatus($langs->trans('TotpStatusEnrolling'), '', '', 'status1', 1);
	} else {
		print dolGetStatus($langs->trans('TotpStatusNone'), '', '', $mandatory ? 'status8' : 'status0', 1);
	}
	if ($mandatory && ($obj->totp_status === null || (int) $obj->totp_status != TotpAuthUser::STATUS_ACTIVE)) {
		$nbmissing++;
		print ' '.img_warning($langs->trans('TotpWillBeForcedNextLogin'));
	}
	print '</td>';
	print '<td class="center">'.($obj->date_activation ? dol_print_date($db->jdate($obj->date_activation), 'dayhour', 'tzuserrel') : '').'</td>';
	print '<td class="center">'.($obj->date_lastuse ? dol_print_date($db->jdate($obj->date_lastuse), 'dayhour', 'tzuserrel') : '').'</td>';
	print '</tr>';
}
print '</table>';

print '<br>'.$langs->trans('TotpUsersSummary', $nbactive, $nb);
if ($nbmissing) {
	print ' &mdash; '.img_warning().' '.$langs->trans('TotpUsersMissing', $nbmissing);
}

print dol_get_fiche_end();

llxFooter();
$db->close();
