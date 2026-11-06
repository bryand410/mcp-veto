# Brancher Token Vault

Ce que je ne peux pas faire à ta place : les clics dans la console Auth0. Ce que
tu ne peux pas faire sans moi : le reste. Suis les quatre étapes, colle les
trois valeurs, et `demo/tokenvault.py` fait la preuve.

## 1. Un compte Auth0

`auth0.com` → *Sign up*. Aucune carte bancaire demandée. Tu obtiens un tenant
dont le domaine ressemble à `dev-abc12345.us.auth0.com`.

Note ce domaine : c'est `AUTH0_DOMAIN`.

## 2. Une application OAuth chez GitHub

GitHub → *Settings* → *Developer settings* → *OAuth Apps* → *New OAuth App*.

| champ | valeur |
|---|---|
| Homepage URL | `https://TON-TENANT.us.auth0.com` |
| Authorization callback URL | `https://TON-TENANT.us.auth0.com/login/callback` |

Génère un *Client Secret*. Note le **Client ID** et le **Client Secret** de
GitHub : ils vont dans Auth0, pas dans le script.

## 3. La connexion GitHub dans Auth0

Auth0 Dashboard → *Authentication* → *Social* → *Create Connection* → **GitHub**.

- colle le Client ID et le Client Secret **GitHub** ;
- onglet *Permissions* : coche `repo` et `read:user` ;
- onglet *Applications* : active la connexion pour l'application créée à
  l'étape 4 (ou crée-la d'abord, l'ordre n'a pas d'importance).

## 4. L'application Auth0

Auth0 Dashboard → *Applications* → *Create Application* → **Regular Web App**.

| champ | valeur |
|---|---|
| Allowed Callback URLs | `http://127.0.0.1:8765/callback` |
| Allowed Logout URLs | `http://127.0.0.1:8765` |

Note *Domain*, *Client ID*, *Client Secret* : c'est `AUTH0_DOMAIN`,
`AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`.

## 5. Lancer

```bash
export AUTH0_DOMAIN=dev-xxxx.us.auth0.com
export AUTH0_CLIENT_ID=...
export AUTH0_CLIENT_SECRET=...
python demo/tokenvault.py
```

Le navigateur s'ouvre, tu autorises GitHub, et le script affiche :

```
1. discovery        issuer, endpoints
2. login            code recu
3. auth0 token      N chars
4. vault            GitHub token, scope, expires_in
5. proof            authenticated as bryand410
6. gated write      URL d'approbation -> tu cliques -> l'issue est creee
```

## Si l'étape 4 échoue

C'est l'étape qui dépend d'un réglage que je n'ai pas pu voir sans tenant :
Token Vault doit être autorisé pour cette connexion. L'erreur exacte le dira.
Colle-la moi, je localise l'interrupteur au lieu de deviner.

Les erreurs typiques à cette étape :

- `invalid_grant` sur `connection` → le nom de connexion n'est pas `github` ;
- `access_denied` / `unauthorized_client` → la connexion n'est pas activée pour
  l'application ;
- `invalid_request` sur `requested_token_type` → Token Vault n'est pas activé
  sur le tenant.

## Ce que ça change pour la soumission

Le critère 1 du challenge — *« Use Token Vault to securely manage the access
tokens »* — sera vrai, avec une preuve exécutable. Le critère 2 (CIBA) reste
implémenté sans Guardian, faute de téléphone, et le script le montre à l'étape 6
puisque l'écriture passe par la porte.

Un relecteur peut vérifier les deux dans le même dépôt public, sans compte.
