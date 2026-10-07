# Dolibarr TOTP — Double authentification pour Dolibarr

Module Dolibarr **TotpAuth** qui ajoute un second facteur à la connexion : après le mot de passe, l'utilisateur saisit un code à 6 chiffres généré par une application d'authentification (Aegis, FreeOTP, Google Authenticator, Microsoft Authenticator, Bitwarden, 1Password…), selon la [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).

Aucun fichier du cœur de Dolibarr n'est modifié : le module repose uniquement sur des hooks standard.

![Dolibarr](https://img.shields.io/badge/Dolibarr-18%2B-blue) ![PHP](https://img.shields.io/badge/PHP-7.4%2B-777bb4) ![Licence](https://img.shields.io/badge/licence-GPLv3-green)

## Fonctionnalités

- **Code TOTP standard** (SHA1, 6 chiffres, période de 30 s, tolérance ±30 s), compatible avec toutes les applications d'authentification.
- **Enrôlement par QR code** depuis l'onglet « Double authentification » de la fiche utilisateur, ou le menu *Utilisateurs & Groupes → Ma double authentification*.
- **10 codes de secours** à usage unique, affichés une seule fois et stockés hachés.
- **Double authentification obligatoire**, au choix : pour personne, pour les administrateurs ou pour tous. Les comptes concernés sans configuration sont guidés à leur connexion suivante.
- **Verrouillage** après plusieurs codes erronés (5 par défaut, pendant 15 minutes), enregistré en base : il reste actif même si l'attaquant rouvre une session.
- **Anti-rejeu** : un code déjà utilisé est refusé, y compris dans une autre session.
- **Secrets chiffrés** en base avec `dolEncrypt()`.
- **Administration** : réinitialisation par un administrateur en cas de perte du téléphone, et page d'état de tous les utilisateurs.
- Interface en **français** et en **anglais**.

## Prérequis

- Dolibarr **18 ou supérieur** (testé sur 22.0.5).
- PHP 7.4 ou supérieur.
- Serveur à l'heure (NTP) : un décalage de plus de 30 secondes fait échouer les codes.

## Installation

Le module se trouve dans le dossier [`totpauth/`](totpauth/) du dépôt. C'est ce dossier, et lui seul, qu'il faut copier dans le répertoire `custom` de Dolibarr : son nom doit rester `totpauth`.

### Installation classique

```bash
git clone https://github.com/nicolasgable/Dolibarr_TOTP.git
cp -r Dolibarr_TOTP/totpauth /chemin/vers/dolibarr/htdocs/custom/
chown -R www-data:www-data /chemin/vers/dolibarr/htdocs/custom/totpauth
```

### Avec l'image Docker officielle de Dolibarr

```bash
git clone https://github.com/nicolasgable/Dolibarr_TOTP.git
docker cp Dolibarr_TOTP/totpauth <conteneur-dolibarr>:/var/www/html/custom/
docker exec <conteneur-dolibarr> chown -R www-data:www-data /var/www/html/custom/totpauth
```

Sans Git, utilisez **Code → Download ZIP** sur GitHub, puis copiez le dossier `totpauth` de l'archive de la même façon.

### Activation

1. Vérifiez dans `conf/conf.php` que `$dolibarr_main_url_root_alt` et `$dolibarr_main_document_root_alt` pointent vers `custom` (c'est le cas par défaut).
2. Dans *Accueil → Configuration → Modules*, activez **TotpAuth** (famille « Interfaces »). La table `llx_totpauth_user` est créée automatiquement.
3. Réglez les options via la roue dentée du module.

> **Avant de rendre la double authentification obligatoire**, activez-la sur votre propre compte administrateur, notez les codes de secours et testez une reconnexion dans une autre fenêtre de navigation.

## Configuration

| Option | Valeur par défaut | Rôle |
|---|---|---|
| Double authentification obligatoire | Non | Non, pour les administrateurs, ou pour tous les utilisateurs |
| Nom affiché dans l'application | Nom de la société | Libellé du compte dans l'application d'authentification |
| Codes erronés avant verrouillage | 5 | Nombre d'échecs consécutifs tolérés |
| Durée du verrouillage | 15 minutes | Blocage de la vérification après les échecs |

## Fonctionnement

Le module s'appuie sur deux hooks de `main.inc.php` :

| Hook | Contexte | Rôle |
|---|---|---|
| `afterLogin` | `login` | Le mot de passe vient d'être accepté. Si l'utilisateur a un TOTP actif, ou doit en configurer un, la session est marquée « en attente » et la requête est aussitôt redirigée vers la page de vérification : la page demandée n'est jamais affichée. |
| `updateSession` | `main` | Appelé à chaque requête d'une session authentifiée. Tant que la session est en attente, toutes les pages redirigent vers la vérification (HTTP 401 pour les appels AJAX et les téléchargements), sauf la déconnexion. |

Une fois le code validé, l'identifiant de session est régénéré.

## Limites connues

- **API REST** : les appels authentifiés par clé d'API (`DOLAPIKEY`) ne passent pas par le formulaire de connexion et ne sont pas soumis au second facteur. Protégez les clés d'API séparément.
- Les autres points d'entrée qui n'utilisent pas de session web (WebDAV, pages publiques) ne sont pas concernés.
- Si le module est désactivé, le second facteur n'est plus demandé. Les configurations sont conservées en base et redeviennent actives à la réactivation.
- Le hook `afterLogin` termine la requête par une redirection : un autre module utilisant aussi `afterLogin` et appelé après celui-ci ne s'exécute pas pour les comptes protégés.

## Récupération d'urgence

Si un administrateur n'a plus ni son téléphone ni ses codes de secours, supprimez sa configuration en base :

```sql
DELETE FROM llx_totpauth_user WHERE fk_user = (SELECT rowid FROM llx_user WHERE login = 'admin');
```

Ou désactivez le module :

```sql
DELETE FROM llx_const WHERE name LIKE 'MAIN_MODULE_TOTPAUTH%';
```

Adaptez le préfixe `llx_` si votre installation en utilise un autre.

## Structure

```
totpauth/
├── core/modules/modTotpAuth.class.php   Descripteur du module
├── class/totp.class.php                 Algorithme TOTP/HOTP et Base32, sans dépendance
├── class/totpauthuser.class.php         Persistance, vérification, verrouillage, codes de secours
├── class/actions_totpauth.class.php     Hooks afterLogin et updateSession
├── lib/totpauth.lib.php                 QR code (via TCPDF, fourni avec Dolibarr) et utilitaires
├── verify.php                           Page de vérification après le mot de passe
├── user_totp.php                        Onglet de la fiche utilisateur
├── admin/setup.php                      Configuration du module
├── admin/users.php                      État de tous les utilisateurs
├── sql/                                 Table llx_totpauth_user
└── langs/fr_FR, langs/en_US             Traductions
```

## Licence

GNU General Public License v3 ou ultérieure.
