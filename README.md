# technet-functions

Azure Functions backing the Tech-Net ticket system. Currently:

- `POST /api/sign` - Generate a signed token for a ticket
- `POST /api/verify` - Verify a signed token

Runtime: Node.js 20, Azure Functions v4 programming model.

## Environment

| Setting | Purpose |
|---------|---------|
| `TECHNET_SIGNING_SECRET` | HMAC-SHA256 signing secret. 32+ random chars. Stored in Azure Key Vault in production; referenced via app setting. |

## Token format

```
base64url({"ticketId":"42","expiry":"2026-04-25T14:30:00Z","nonce":"..."}).base64url(HMAC-SHA256(payload, secret))
```

The two parts are joined by a single `.`.

## Deployment

Push to `main`. GitHub Actions builds and deploys to the Function App
(workflow configured on first run).

## Local run

```
npm install
func start
```

Set `TECHNET_SIGNING_SECRET` in `local.settings.json` before running.
