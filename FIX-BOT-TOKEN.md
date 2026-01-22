# Fix: Worker Bot Token Invalid

The Cloudflare Worker has an invalid `TELEGRAM_BOT_TOKEN`. When it tries to send notifications to Telegram, it gets a 404 error.

## Symptom

Notifications fall back to direct send, and replies get "notification has expired" because the Worker has no message→session mapping.

## Fix

Re-set the bot token secret using file input (avoid `echo` which can add extra characters):

```bash
cd ~/projects/ccr-worker
export CLOUDFLARE_API_TOKEN="$(cat /run/secrets/cloudflare_api_token)"

# Extract token from CCR .env and set as secret
grep -o 'TELEGRAM_BOT_TOKEN=.*' ~/projects/claude-code-remote/.env | cut -d= -f2 > /tmp/bot_token.txt
wrangler secret put TELEGRAM_BOT_TOKEN < /tmp/bot_token.txt
rm /tmp/bot_token.txt
```

## Verify

Test notification through Worker:

```bash
# First register a test session
curl -s -X POST https://ccr-router.jonathan-mohrbacher.workers.dev/sessions/register \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test","machineId":"devbox","label":"test"}'

# Send notification
curl -s -X POST https://ccr-router.jonathan-mohrbacher.workers.dev/notifications/send \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test","chatId":8248645256,"text":"Bot token test"}'

# Clean up
curl -s -X POST https://ccr-router.jonathan-mohrbacher.workers.dev/sessions/unregister \
  -H 'Content-Type: application/json' \
  -d '{"sessionId":"test"}'
```

Should return `{"ok":true,"messageId":...}` and you should receive the message in Telegram.
