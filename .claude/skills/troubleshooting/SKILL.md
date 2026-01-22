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

**Fix:** Re-set secrets using file input:

```bash
cd ~/projects/ccr-worker
export CLOUDFLARE_API_TOKEN="$(cat /run/secrets/cloudflare_api_token)"

# Bot token (fixes 404)
grep -o 'TELEGRAM_BOT_TOKEN=.*' ~/projects/claude-code-remote/.env | cut -d= -f2 > /tmp/secret.txt
wrangler secret put TELEGRAM_BOT_TOKEN < /tmp/secret.txt
rm /tmp/secret.txt

# Webhook secret (fixes 401)
grep -o 'TELEGRAM_WEBHOOK_SECRET=.*' ~/projects/claude-code-remote/.env | cut -d= -f2 > /tmp/secret.txt
wrangler secret put TELEGRAM_WEBHOOK_SECRET < /tmp/secret.txt
rm /tmp/secret.txt
```

**Verify:**

```bash
source ~/projects/claude-code-remote/.env
curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getWebhookInfo" | jq '{url, last_error_message}'
```

## Check Worker Status

```bash
# Health check
curl https://ccr-router.jonathan-mohrbacher.workers.dev/health

# View registered sessions
curl https://ccr-router.jonathan-mohrbacher.workers.dev/sessions | jq
```

## View Worker Logs

1. Go to Cloudflare Dashboard → Workers & Pages
2. Select `ccr-router`
3. Click "Logs" tab
4. Enable "Real-time Logs"

## Test Notification Flow

```bash
# Register test session
curl -X POST https://ccr-router.jonathan-mohrbacher.workers.dev/sessions/register \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test","machineId":"devbox","label":"test"}'

# Send notification (replace YOUR_CHAT_ID)
curl -X POST https://ccr-router.jonathan-mohrbacher.workers.dev/notifications/send \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test","chatId":YOUR_CHAT_ID,"text":"Test message"}'

# Clean up
curl -X POST https://ccr-router.jonathan-mohrbacher.workers.dev/sessions/unregister \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test"}'
```

## Machine Agent Not Connecting

Check CCR logs for connection status:

```bash
npm run webhooks:log
# Look for: [MachineAgent] [INFO] Connected to Worker as <machine-id>
```

If not connecting:
1. Verify `CCR_WORKER_URL` in CCR `.env`
2. Verify `CCR_MACHINE_ID` is set and unique per machine
3. Check Worker is deployed: `curl .../health`

## Commands Going to Wrong Machine

Each machine needs unique `CCR_MACHINE_ID`:

```bash
# devbox .env
CCR_MACHINE_ID=devbox

# macOS .env
CCR_MACHINE_ID=macbook
```
