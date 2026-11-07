# Brancher Token Vault

Ce document a été écrit **après** que le parcours ait tourné de bout en bout sur
un vrai compte GitHub, pas avant. Chaque piège listé ici a été rencontré et
mesuré, pas imaginé.

Deux fichiers :

- `demo/auth0_setup.py` — met le tenant dans l'état attendu, par l'API
  Management. Idempotent : il lit, compare, corrige.
- `demo/tokenvault.py` — la preuve exécutable, en huit étapes numérotées.

## Ce qu'il faut, dans l'ordre

### 1. Un tenant Auth0

`auth0.com` → *Sign up*. Sans carte bancaire. Tu obtiens
`dev-xxxxxxxx.us.auth0.com` — c'est `AUTH0_DOMAIN`.

### 2. Une application Regular Web App

*Applications* → *Create Application* → **Regular Web App**.

| champ | valeur |
|---|---|
| Allowed Callback URLs | `http://127.0.0.1:8765/callback` |
| Allowed Logout URLs | `http://127.0.0.1:8765` |

Puis *Advanced Settings* → *Grant Types* : coche **Authorization Code**,
**Refresh Token** et **Token Vault**.

Et *Advanced Settings* → *Refresh Token* : **rotation désactivée**. Token Vault
ne sait pas suivre un refresh token qui tourne.

Note *Domain*, *Client ID*, *Client Secret* : c'est `AUTH0_DOMAIN`,
`AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`.

### 3. Une OAuth App GitHub — pas les dev keys

GitHub → *Settings* → *Developer settings* → *OAuth Apps* → **New OAuth App**.

| champ | valeur |
|---|---|
| Homepage URL | `https://TON-TENANT.us.auth0.com` |
| Authorization callback URL | `https://TON-TENANT.us.auth0.com/login/callback` |

Génère un *Client Secret*. Ces deux valeurs vont dans Auth0, jamais dans le
script.

**Ne saute pas cette étape.** Une connexion GitHub créée sans Client ID/Secret
utilise les *developer keys* d'Auth0, et le flux de connexion les refuse
explicitement :

```
400  The connect flow cannot be used with dev keys.
```

### 4. La connexion GitHub

*Authentication* → *Social* → **GitHub** : colle le Client ID et le Client
Secret GitHub, onglet *Permissions* → `repo`, `read:user`, onglet
*Applications* → active l'application de l'étape 2.

L'onglet *Connected Accounts* (Token Vault) doit être actif. `auth0_setup.py`
vérifie les trois : identifiants, scopes, `connected_accounts.active`.

### 5. Les deux grants My Account API

C'est le piège qui coûte le plus de temps, parce que le message d'erreur ne le
dit pas.

Le flux de connexion passe par la **My Account API**
(`https://TON-TENANT.us.auth0.com/me/`). Il faut deux *client grants* sur cette
API, avec `create:me:connected_accounts`, `read:me:connected_accounts` et
`delete:me:connected_accounts` :

| `subject_type` | à quoi ça sert |
|---|---|
| `user` | le `/authorize` du login — sans lui : `Client is not authorized to access resource server ".../me/"` |
| `client` | les appels MCP / machine |

Un seul des deux ne suffit pas. `auth0_setup.py` crée les deux.

### 6. L'accès Management API

`auth0_setup.py` pilote le tenant, il lui faut donc un token. *Applications* →
ton app → onglet **API Access** → ligne **Auth0 Management API** → *Edit* →
colonne **Client Access** → toutes les permissions → *Save*.

Attention : la colonne *User-delegated Access* ne suffit pas pour
`client_credentials`. C'est *Client Access* qui compte.

```bash
export AUTH0_DOMAIN=dev-xxxx.us.auth0.com
export AUTH0_CLIENT_ID=...
export AUTH0_CLIENT_SECRET=...
python demo/auth0_setup.py
```

### 7. Lancer la preuve

```bash
export AUTH0_DOMAIN=dev-xxxx.us.auth0.com
export AUTH0_CLIENT_ID=...
export AUTH0_CLIENT_SECRET=...
python demo/tokenvault.py
```

Deux onglets s'ouvrent : le login, puis le consentement GitHub qui **lie** le
compte au coffre. À la fin, une troisième page demande l'approbation de
l'écriture — c'est mcp-veto qui la retient.

Sortie attendue :

```
2. login, asking for a token the My Account API will accept
   code received
   My Account token: 952 chars
   refresh token  : 45 chars

3. ask the My Account API to link github
   auth_session: smx2GcL8Q4dk...
   connect_uri : https://dev-xxxx.us.auth0.com/connected-accounts/connect

4. consent: the browser is opening on github
   connect_code received

5. the My Account API stores the tokens
   connected account: cac_...
   scopes           : ['read:user', 'repo']
   access_type      : offline

6. refresh token -> GitHub token, out of the vault
   exchange    : refresh token
   GitHub token: 40 chars
   scope       : read:user repo
   expires_in  : 28797

7. the vaulted token really is GitHub's
   authenticated as: bryand410 (18 public repos)

8. a write with that token, held by mcp-veto
   needs approval: create_issue on bryand410/mcp-veto
   -> http://127.0.0.1:63699/a/...
   approved. sending with the vaulted token.
   created: https://github.com/bryand410/mcp-veto/issues/2
```

## Les erreurs rencontrées, et ce qu'elles voulaient dire

| message | cause réelle |
|---|---|
| `Client ... is not authorized to access resource server ".../api/v2/"` | pas de client grant sur la Management API (colonne *Client Access*) |
| `Client ... is not authorized to access resource server ".../me/"` | grant My Account API manquant, ou avec `subject_type: client` alors que le login veut `user` |
| `The connect flow cannot be used with dev keys` | connexion GitHub sans OAuth App à toi |
| `federated_connection_refresh_token_not_found` | login social ordinaire : il ne crée **pas** de connected account, il faut le flux `/me/v1/connected-accounts/connect` |
| `Not supported JWT type in subject token` | échange par *access token* : il exige un Custom API Client lié à l'`aud` du token |
| `Additional properties not allowed: enabled_clients` | `enabled_clients` est en lecture seule depuis la refonte API Access ; l'attachement se lit sur `/connections/{id}/clients` |

## Les deux échanges, et lequel choisir

- **Refresh token** (`subject_token_type:
  urn:ietf:params:oauth:token-type:refresh_token`) — celui d'une web app, celui
  qui marche ici, aucune infrastructure en plus.
- **Access token** — pour une API qui reçoit un token d'un SPA. Demande un
  *Custom API Client* dont l'identifiant est celui de l'API cible. Plus lourd,
  et inutile dans ce démo.

## Ce que ça change pour la soumission

Le critère 1 du challenge — *« Use Token Vault to securely manage the access
tokens »* — n'est plus une affirmation, c'est une sortie de console
reproductible, avec l'identifiant du connected account et l'URL de l'issue
créée. Le token GitHub n'a jamais transité par le disque ni par le code : il
sort du coffre au moment de l'appel, et meurt avec le processus.

Le critère 2 (CIBA) reste implémenté sans Guardian, faute de téléphone : le
démo le montre à l'étape 8, où l'écriture attend une approbation hors bande
avant de partir.
