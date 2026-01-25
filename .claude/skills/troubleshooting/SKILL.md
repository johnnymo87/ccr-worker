---
name: troubleshooting
description: Use when Worker is returning errors, notifications fail, or commands aren't routing correctly
---

# Troubleshooting CCR Worker

## Telegram 404 or 401 Errors

Worker secrets may be corrupted from shell escaping when set via `echo | wrangler secret put`.

| Error | Cause |
|-------|-------|
| 404 | Bot token invalid |
| 401 Unauthorized | Webhook secret mismatch |

**Fix:** Re-set secrets by piping directly from sops-nix:

```bash
cd ~/projects/ccr-worker
export CLOUDFLARE_API_TOKEN="$(cat /run/secrets/cloudflare_api_token)"

# Bot token (fixes 404)
cat /run/secrets/telegram_bot_token | wrangler secret put TELEGRAM_BOT_TOKEN

# Webhook secret (fixes 401)
cat /run/secrets/telegram_webhook_secret | wrangler secret put TELEGRAM_WEBHOOK_SECRET
```

**Verify:**

```bash
curl -s "https://api.telegram.org/bot$(cat /run/secrets/telegram_bot_token)/getWebhookInfo" | jq '{url, last_error_message}'
```

## Check Worker Status

Replace `your-account` with your Cloudflare account subdomain:

```bash
# Health check
curl https://ccr-router.your-account.workers.dev/health

# View registered sessions
curl https://ccr-router.your-account.workers.dev/sessions | jq
```

## View Worker Logs

**Via CLI:**
```bash
export CLOUDFLARE_API_TOKEN="$(cat /run/secrets/cloudflare_api_token)"
wrangler tail --format=pretty
```

**Via Dashboard:**
1. Go to Cloudflare Dashboard → Workers & Pages
2. Select `ccr-router`
3. Click "Logs" tab
4. Enable "Real-time Logs"

## Test Notification Flow

```bash
WORKER_URL="https://ccr-router.your-account.workers.dev"  # Replace with your URL
CHAT_ID="your-chat-id"  # Replace with your Telegram chat ID

# Register test session
curl -X POST "${WORKER_URL}/sessions/register" \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test","machineId":"devbox","label":"test"}'

# Send notification
curl -X POST "${WORKER_URL}/notifications/send" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionId\":\"test\",\"chatId\":${CHAT_ID},\"text\":\"Test message\"}"

# Clean up
curl -X POST "${WORKER_URL}/sessions/unregister" \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test"}'
```

## Machine Agent Not Connecting

Check CCR logs for connection status:

```bash
# Devbox
devenv shell
ccr-start npm run webhooks:log

# macOS
devenv shell
secretspec run -- npm run webhooks:log

# Look for: [MachineAgent] [INFO] Authenticated and connected as <machine-id>
```

If not connecting:
1. Verify `CCR_WORKER_URL` in secretspec.toml or secret storage
2. Verify `CCR_MACHINE_ID` is set and unique per machine
3. Verify `CCR_API_KEY` matches between agent and Worker
4. Check Worker is deployed: `curl .../health`

## Commands Going to Wrong Machine

Each machine needs unique `CCR_MACHINE_ID`:
- **Devbox**: Hardcoded in `ccr-start` script (set to "devbox")
- **macOS**: Stored in Keychain via SecretSpec

Check current sessions:
```bash
curl https://ccr-router.your-account.workers.dev/sessions | jq
```

## WebSocket Connection Drops

Durable Objects hibernate after ~60s of inactivity. This is normal - MachineAgent auto-reconnects:

```
[MachineAgent] [WARN] WebSocket closed (1006: ), reconnecting...
[MachineAgent] [INFO] Authenticated and connected as devbox
```

## Durable Object Errors

If seeing "Durable Object not found" or similar:

1. Check wrangler.toml has correct bindings
2. Redeploy: `wrangler deploy`
3. If persists, check Cloudflare Dashboard for DO errors
