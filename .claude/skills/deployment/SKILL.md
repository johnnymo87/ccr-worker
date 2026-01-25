---
name: deployment
description: Use when deploying or updating the CCR Worker to Cloudflare
---

# Deploying CCR Worker

## Prerequisites

- Cloudflare account with Workers enabled
- `wrangler` CLI installed
- Access to `CLOUDFLARE_API_TOKEN` secret (from sops-nix on devbox)

## Authentication

```bash
export CLOUDFLARE_API_TOKEN="$(cat /run/secrets/cloudflare_api_token)"
```

## Setting Secrets

Secrets should be piped directly from sops-nix to avoid shell escaping issues.

```bash
cd ~/projects/ccr-worker

# From sops-nix (devbox)
cat /run/secrets/telegram_bot_token | wrangler secret put TELEGRAM_BOT_TOKEN
cat /run/secrets/telegram_webhook_secret | wrangler secret put TELEGRAM_WEBHOOK_SECRET
cat /run/secrets/ccr_api_key | wrangler secret put CCR_API_KEY

# Verify
wrangler secret list
```

## Deploy

```bash
wrangler deploy
```

## Update Telegram Webhook

After first deployment, point Telegram to the Worker:

```bash
# Read secrets from sops-nix
BOT_TOKEN="$(cat /run/secrets/telegram_bot_token)"
WEBHOOK_SECRET="$(cat /run/secrets/telegram_webhook_secret)"
PATH_SECRET="$(cat /run/secrets/telegram_webhook_path_secret)"
WORKER_URL="https://ccr-router.your-account.workers.dev"  # Replace with your Worker URL

curl -X POST "https://api.telegram.org/bot${BOT_TOKEN}/setWebhook" \
  -H "Content-Type: application/json" \
  -d "{
    \"url\": \"${WORKER_URL}/webhook/telegram/${PATH_SECRET}\",
    \"secret_token\": \"${WEBHOOK_SECRET}\"
  }"
```

## Verify Deployment

```bash
# Health check (replace with your Worker URL)
curl https://ccr-router.your-account.workers.dev/health
# Should return: ok

# Check registered sessions
curl https://ccr-router.your-account.workers.dev/sessions | jq
```

## Rollback

If deployment breaks functionality:

```bash
# View deployment history
wrangler deployments list

# Roll back to previous version
wrangler rollback
```

## Troubleshooting Deployment

### "Could not route to /health"

Durable Object binding not configured. Check `wrangler.toml` has:
```toml
[[durable_objects.bindings]]
name = "ROUTER"
class_name = "RouterDurableObject"
```

### Secrets not updating

Secrets may take 30-60 seconds to propagate. Wait and test again.

### API token issues

Verify token has correct permissions:
- Workers Scripts: Edit
- Workers KV Storage: Edit (if using KV)
- D1: Edit (if using D1)
