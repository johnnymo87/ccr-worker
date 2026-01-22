# CCR Router Worker

Cloudflare Worker that routes Telegram webhooks to the correct Claude Code Remote instance across multiple machines.

## Architecture

```
Telegram → Worker → WebSocket → Machine Agent → Claude Session
                ↓
         Durable Object
         (session registry)
```

- **Durable Object**: Stores session→machine mappings in SQLite
- **WebSocket**: Machine agents maintain persistent connections
- **Webhook**: Receives Telegram updates, routes to correct machine

## Deployment

```bash
# Authenticate (uses CLOUDFLARE_API_TOKEN from environment)
export CLOUDFLARE_API_TOKEN="$(cat /run/secrets/cloudflare_api_token)"

# Set secrets (use file input to avoid shell escaping issues)
grep -o 'TELEGRAM_BOT_TOKEN=.*' ~/projects/claude-code-remote/.env | cut -d= -f2 > /tmp/token.txt
wrangler secret put TELEGRAM_BOT_TOKEN < /tmp/token.txt
rm /tmp/token.txt

grep -o 'TELEGRAM_WEBHOOK_SECRET=.*' ~/projects/claude-code-remote/.env | cut -d= -f2 > /tmp/secret.txt
wrangler secret put TELEGRAM_WEBHOOK_SECRET < /tmp/secret.txt
rm /tmp/secret.txt

# Deploy
wrangler deploy
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sessions/register` | POST | Register session with machine |
| `/sessions/unregister` | POST | Remove session |
| `/sessions` | GET | List all sessions |
| `/notifications/send` | POST | Send notification via Worker |
| `/webhook/telegram/{secret}` | POST | Telegram webhook receiver |
| `/ws?machineId=X` | WebSocket | Machine agent connection |
| `/health` | GET | Health check |

## Troubleshooting

### Check Worker is running

```bash
curl https://ccr-router.jonathan-mohrbacher.workers.dev/health
# Should return: ok
```

### Check registered sessions

```bash
curl https://ccr-router.jonathan-mohrbacher.workers.dev/sessions | jq
```

### Test notification sending

```bash
# Register test session
curl -X POST https://ccr-router.jonathan-mohrbacher.workers.dev/sessions/register \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test","machineId":"devbox","label":"test"}'

# Send notification
curl -X POST https://ccr-router.jonathan-mohrbacher.workers.dev/notifications/send \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test","chatId":YOUR_CHAT_ID,"text":"Test message"}'

# Clean up
curl -X POST https://ccr-router.jonathan-mohrbacher.workers.dev/sessions/unregister \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test"}'
```

### Telegram 404 or 401 errors

If Worker fails with Telegram errors, secrets may be corrupted from shell escaping:
- **404**: Bot token invalid
- **401 Unauthorized**: Webhook secret mismatch

Re-set using file input (avoids shell escaping issues):

```bash
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

### View Worker logs

1. Go to Cloudflare Dashboard → Workers & Pages
2. Select `ccr-router`
3. Click "Logs" tab
4. Enable "Real-time Logs"

## Related

- [claude-code-remote](https://github.com/johnnymo87/claude-code-remote) - The notification relay system
- Worker deployed at: `https://ccr-router.jonathan-mohrbacher.workers.dev`
