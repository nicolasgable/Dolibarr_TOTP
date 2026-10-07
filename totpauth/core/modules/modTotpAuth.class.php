<?php
/* Copyright (C) 2026 AllSafe
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

/**
 * \defgroup totpauth Module TotpAuth
 * \brief    Two-factor authentication (TOTP, RFC 6238) for Dolibarr logins.
 * \file     totpauth/core/modules/modTotpAuth.class.php
 * \ingroup  totpauth
 */

include_once DOL_DOCUMENT_ROOT.'/core/modules/DolibarrModules.class.php';

class modTotpAuth extends DolibarrModules
{
	/**
	 * @param DoliDB $db Database handler
	 */
	public function __construct($db)
	{
		global $conf;

		$this->db = $db;

		// Id for module. Choose a free number in the "external modules" range if this one is already used.
		$this->numero = 500710;
		$this->rights_class = 'totpauth';
		$this->family = 'interface';
		$this->module_position = '90';
		$this->name = preg_replace('/^mod/i', '', get_class($this));
		$this->description = 'TotpAuthDescription';
		$this->descriptionlong = 'TotpAuthDescriptionLong';
		$this->editor_name = 'AllSafe';
		$this->editor_url = 'https://allsafe.ovh';
		$this->version = '1.0.0';
		$this->const_name = 'MAIN_MODULE_'.strtoupper($this->name);
		$this->picto = 'lock';

		$this->module_parts = array(
			'triggers' => 0,
			'login' => 0,
			// "login" context: hook afterLogin. "main" context: hook updateSession (every authenticated request).
			'hooks' => array('login', 'main'),
		);

		$this->dirs = array();
		$this->config_page_url = array('setup.php@totpauth');

		$this->depends = array();
		$this->requiredby = array();
		$this->conflictwith = array();
		$this->langfiles = array('totpauth@totpauth');
		$this->phpmin = array(7, 4);
		$this->need_dolibarr_version = array(18, 0);

		$this->warnings_activation = array();

		$this->const = array(
			0 => array('TOTPAUTH_FORCE', 'chaine', '0', 'Second factor mandatory: 0=no, 1=admins, 2=everybody', 0, 'current', 0),
			1 => array('TOTPAUTH_MAX_FAILS', 'chaine', '5', 'Failed codes before lock', 0, 'current', 0),
			2 => array('TOTPAUTH_LOCK_MINUTES', 'chaine', '15', 'Lock duration in minutes', 0, 'current', 0),
		);

		if (!isset($conf->totpauth) || !isset($conf->totpauth->enabled)) {
			$conf->totpauth = new stdClass();
			$conf->totpauth->enabled = 0;
		}

		// Tab on user card
		$this->tabs = array(
			array('data' => 'user:+totpauth:TotpTabTitle:totpauth@totpauth:1:/totpauth/user_totp.php?id=__ID__'),
		);

		$this->dictionaries = array();
		$this->boxes = array();
		$this->cronjobs = array();

		// Permissions
		$this->rights = array();
		$r = 0;
		$this->rights[$r][0] = $this->numero.'01';
		$this->rights[$r][1] = 'Reset the second factor of other users';
		$this->rights[$r][3] = 0;
		$this->rights[$r][4] = 'manage';
		$this->rights[$r][5] = '';
		$r++;

		// Menu: shortcut in "Users & Groups"
		$this->menu = array();
		$r = 0;
		$this->menu[$r++] = array(
			'fk_menu' => 'fk_mainmenu=home,fk_leftmenu=users',
			'type' => 'left',
			'titre' => 'TotpMyTwoFactor',
			'mainmenu' => 'home',
			'leftmenu' => 'totpauth',
			'url' => '/totpauth/user_totp.php',
			'langs' => 'totpauth@totpauth',
			'position' => 1000 + $r,
			'enabled' => 'isModEnabled("totpauth")',
			'perms' => '1',
			'target' => '',
			'user' => 2,
		);
	}

	/**
	 * Called when module is enabled.
	 *
	 * @param  string $options Options when enabling module ('', 'noboxes')
	 * @return int             1 if OK, 0 if KO
	 */
	public function init($options = '')
	{
		$result = $this->_load_tables('/totpauth/sql/');
		if ($result < 0) {
			return -1;
		}
		$this->remove($options);
		$sql = array();
		return $this->_init($sql, $options);
	}

	/**
	 * Called when module is disabled. Data (table llx_totpauth_user) is kept.
	 *
	 * @param  string $options Options when disabling module
	 * @return int             1 if OK, 0 if KO
	 */
	public function remove($options = '')
	{
		$sql = array();
		return $this->_remove($sql, $options);
	}
}
