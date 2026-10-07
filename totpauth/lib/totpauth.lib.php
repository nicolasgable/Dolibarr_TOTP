<?php
/* Copyright (C) 2026 AllSafe
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * \file    totpauth/lib/totpauth.lib.php
 * \ingroup totpauth
 * \brief   Helper functions for module TotpAuth.
 */

/**
 * Tell if the second factor is mandatory for this user, according to module setup.
 * TOTPAUTH_FORCE: 0 = optional, 1 = mandatory for admin users, 2 = mandatory for everybody.
 *
 * @param  User $u User
 * @return bool
 */
function totpauth_is_mandatory($u)
{
	$mode = getDolGlobalInt('TOTPAUTH_FORCE');
	if ($mode == 2) {
		return true;
	}
	if ($mode == 1 && !empty($u->admin)) {
		return true;
	}
	return false;
}

/**
 * Issuer shown in authenticator apps.
 *
 * @return string
 */
function totpauth_issuer()
{
	$issuer = getDolGlobalString('TOTPAUTH_ISSUER');
	if ($issuer === '') {
		$issuer = getDolGlobalString('MAIN_INFO_SOCIETE_NOM', 'Dolibarr');
	}
	return $issuer;
}

/**
 * Return an inline SVG QR code, using the TCPDF library shipped with Dolibarr.
 *
 * @param  string $text Text to encode
 * @return string       SVG markup, or '' if the library is not available
 */
function totpauth_qr_svg($text)
{
	$file = DOL_DOCUMENT_ROOT.'/includes/tecnickcom/tcpdf/tcpdf_barcodes_2d.php';
	if (!is_readable($file)) {
		return '';
	}
	require_once $file;
	$barcode = new TCPDF2DBarcode($text, 'QRCODE,M');
	$svg = $barcode->getBarcodeSVGcode(5, 5, 'black');
	// Remove the XML prolog / doctype to embed the SVG inline
	$pos = strpos($svg, '<svg');
	if ($pos === false) {
		return '';
	}
	$svg = substr($svg, $pos);
	// TCPDF copies the encoded text (so the secret) into a <desc> tag: remove it
	$svg = preg_replace('/<desc>.*?<\/desc>/s', '', $svg);
	// White background so the code stays readable in dark themes
	return '<div style="display:inline-block;background:#fff;padding:12px;border-radius:6px;line-height:0">'.$svg.'</div>';
}

/**
 * Keep only a local relative URL, to avoid open redirects after the challenge.
 *
 * @param  string $url URL
 * @return string      Safe URL
 */
function totpauth_safe_backurl($url)
{
	$url = (string) $url;
	if ($url === '' || $url[0] !== '/' || strpos($url, '//') === 0 || strpos($url, '\\') !== false
		|| preg_match('/[\r\n]/', $url) || preg_match('/(logout|totpauth\/verify)\.php/', $url)) {
		return DOL_URL_ROOT.'/index.php';
	}
	return $url;
}

/**
 * Format the secret by groups of 4 chars, easier to type by hand.
 *
 * @param  string $secret Base32 secret
 * @return string
 */
function totpauth_format_secret($secret)
{
	return trim(chunk_split($secret, 4, ' '));
}

/**
 * HTML block that shows recovery codes once.
 *
 * @param  string[]  $codes Clear codes
 * @param  Translate $langs Translation object
 * @return string
 */
function totpauth_print_backup_codes($codes, $langs)
{
	$out = '<div class="totpauth-codes">';
	$out .= '<p><strong>'.$langs->trans('TotpBackupCodesTitle').'</strong></p>';
	$out .= '<p class="opacitymedium">'.$langs->trans('TotpBackupCodesHelp').'</p>';
	$out .= '<pre style="font-size:1.15em;line-height:1.7em;padding:10px 16px;display:inline-block;border:1px dashed #888;border-radius:6px">';
	foreach ($codes as $i => $c) {
		$out .= dol_escape_htmltag($c).(($i % 2) ? "\n" : '    ');
	}
	$out .= '</pre></div>';
	return $out;
}

/**
 * Tabs of the admin setup page.
 *
 * @return array<array{0:string,1:string,2:string}>
 */
function totpauthAdminPrepareHead()
{
	global $langs;
	$h = 0;
	$head = array();
	$head[$h][0] = dol_buildpath('/totpauth/admin/setup.php', 1);
	$head[$h][1] = $langs->trans('Settings');
	$head[$h][2] = 'settings';
	$h++;
	$head[$h][0] = dol_buildpath('/totpauth/admin/users.php', 1);
	$head[$h][1] = $langs->trans('TotpUsersStatus');
	$head[$h][2] = 'users';
	$h++;
	return $head;
}
