---
name: deployment
description: Use when deploying or updating the CCR Worker to Cloudflare
---

# Deploying CCR Worker

## Prerequisites

- Cloudflare account with Workers enabled
- `wrangler` CLI installed
- Access to `CLOUDFLARE_API_TOKEN` secret

## Authentication

```bash
export CLOUDFLARE_API_TOKEN="$(cat /run/secrets/cloudflare_api_token)"
```

## Setting Secrets

**IMPORTANT:** Always use file input to avoid shell escaping issues.

```bash
cd ~/projects/ccr-worker

# Bot token
grep -o 'TELEGRAM_BOT_TOKEN=.*' ~/projects/claude-code-remote/.env | cut -d= -f2 > /tmp/token.txt
wrangler secret put TELEGRAM_BOT_TOKEN < /tmp/token.txt
rm /tmp/token.txt

# Webhook secret
grep -o 'TELEGRAM_WEBHOOK_SECRET=.*' ~/projects/claude-code-remote/.env | cut -d= -f2 > /tmp/secret.txt
wrangler secret put TELEGRAM_WEBHOOK_SECRET < /tmp/secret.txt
rm /tmp/secret.txt
```

## Deploy

```bash
wrangler deploy
```

## Update Telegram Webhook

After first deployment, point Telegram to the Worker:

```bash
source ~/projects/claude-code-remote/.env
curl -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook" \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"https://ccr-router.jonathan-mohrbacher.workers.dev/webhook/telegram/$TELEGRAM_WEBHOOK_SECRET\"}"
```

## Verify Deployment

```bash
# Health check
curl https://ccr-router.jonathan-mohrbacher.workers.dev/health
# Should return: ok

# Check registered sessions
curl https://ccr-router.jonathan-mohrbacher.workers.dev/sessions | jq
```
