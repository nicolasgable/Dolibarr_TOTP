# TotpAuth — Double authentification TOTP pour Dolibarr

Module Dolibarr qui ajoute un second facteur à la connexion : après le mot de passe, l'utilisateur saisit un code à 6 chiffres généré par une application d'authentification (Aegis, FreeOTP, Google Authenticator, Bitwarden, 1Password…), conformément à la RFC 6238.

## Fonctionnalités

- **Code TOTP** standard (SHA1, 6 chiffres, 30 s, tolérance ±30 s) — compatible avec toutes les applications du marché.
- **Enrôlement par QR code** depuis l'onglet « Double authentification » de la fiche utilisateur (ou menu *Utilisateurs & Groupes → Ma double authentification*).
- **10 codes de secours** à usage unique, affichés une seule fois, stockés hachés (`password_hash`).
- **Double authentification obligatoire** au choix : pour personne, pour les administrateurs, ou pour tous. Les comptes concernés sans configuration sont guidés à la connexion suivante.
- **Verrouillage** après N codes erronés (5 par défaut) pendant X minutes (15 par défaut), compté en base et donc valable même si l'attaquant rouvre une session.
- **Anti-rejeu** : un code déjà utilisé est refusé, même dans une autre session.
- **Secrets chiffrés** en base avec `dolEncrypt()` (clé : `$dolibarr_main_instance_unique_id` de `conf.php`).
- **Réinitialisation par un administrateur** (perte de téléphone), et page de synthèse de l'état de tous les utilisateurs.
- Désactivation ou régénération des codes de secours par l'utilisateur : nécessite un code TOTP valide.

## Prérequis

- Dolibarr **18 ou supérieur** (testé sur 22.0.5) — PHP 7.4+.
- L'heure du serveur doit être juste (NTP) : un décalage de plus de 30 s fait échouer les codes.

## Installation

1. Copier le dossier `totpauth` dans le répertoire `custom` de Dolibarr :
   - installation classique : `htdocs/custom/totpauth`
   - image Docker officielle : le volume monté sur `/var/www/html/custom`

   Exemple avec le conteneur `dolibarr-web` :
   ```bash
   docker cp totpauth dolibarr-web:/var/www/html/custom/
   docker exec dolibarr-web chown -R www-data:www-data /var/www/html/custom/totpauth
   ```
2. Vérifier dans `conf/conf.php` que `$dolibarr_main_url_root_alt` et `$dolibarr_main_document_root_alt` pointent bien vers `custom` (c'est le cas par défaut).
3. *Accueil → Configuration → Modules* : activer **TotpAuth** (famille « Interfaces »). La table `llx_totpauth_user` est créée automatiquement.
4. Configurer via la roue dentée du module.

> **Conseil de déploiement** : activez d'abord la double authentification sur votre propre compte admin et testez une déconnexion/reconnexion **dans une autre fenêtre de navigation** avant de la rendre obligatoire. Notez les codes de secours.

## Fonctionnement technique

Le module s'appuie uniquement sur deux hooks standard de `main.inc.php` (aucune modification du cœur) :

| Hook | Contexte | Rôle |
|---|---|---|
| `afterLogin` | `login` | Le mot de passe vient d'être accepté. Si l'utilisateur a un TOTP actif (ou doit en configurer un), la session est marquée « en attente » et la requête est immédiatement redirigée vers `verify.php` — la page demandée n'est jamais affichée. |
| `updateSession` | `main` | Appelé à chaque requête d'une session déjà authentifiée. Tant que la session est en attente, toutes les pages redirigent vers `verify.php` (HTTP 401 pour les appels AJAX / téléchargements), sauf la déconnexion. |

Après validation, l'identifiant de session est régénéré.

## Limites connues

- **API REST** : les appels par clé d'API (`DOLAPIKEY`) ne passent pas par le formulaire de connexion et ne sont pas soumis au second facteur. Protégez les clés d'API séparément.
- **Autres points d'entrée** qui authentifient sans session web (WebDAV, pages publiques) ne sont pas concernés.
- Si le module est **désactivé**, la double authentification n'est plus demandée (les configurations sont conservées en base et redeviennent actives à la réactivation).
- Le hook `afterLogin` termine la requête par une redirection : un autre module qui utiliserait aussi `afterLogin` et serait appelé après celui-ci ne s'exécuterait pas pour les comptes protégés.

## Récupération d'urgence (admin bloqué sans téléphone ni codes de secours)

Supprimer la configuration directement en base :
```sql
DELETE FROM llx_totpauth_user WHERE fk_user = (SELECT rowid FROM llx_user WHERE login = 'admin');
```
ou désactiver le module :
```sql
DELETE FROM llx_const WHERE name LIKE 'MAIN_MODULE_TOTPAUTH%';
```

## Fichiers

```
totpauth/
├── core/modules/modTotpAuth.class.php   Descripteur du module
├── class/totp.class.php                 Algorithme TOTP/HOTP + Base32 (sans dépendance)
├── class/totpauthuser.class.php         Persistance, vérification, verrouillage, codes de secours
├── class/actions_totpauth.class.php     Hooks afterLogin / updateSession
├── lib/totpauth.lib.php                 QR code (TCPDF intégré à Dolibarr), utilitaires
├── verify.php                           Page de vérification après mot de passe
├── user_totp.php                        Onglet de la fiche utilisateur
├── admin/setup.php, admin/users.php     Configuration et état des utilisateurs
├── sql/                                 Table llx_totpauth_user
└── langs/fr_FR, langs/en_US
```

Licence GPL v3 ou ultérieure.
