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

## Quick Start

```bash
# Authenticate
export CLOUDFLARE_API_TOKEN="$(cat /run/secrets/cloudflare_api_token)"

# Deploy
cd ~/projects/ccr-worker
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

## Skills

| Skill | Description |
|-------|-------------|
| [Deployment](.claude/skills/deployment/SKILL.md) | Deploy and update the Worker |
| [Troubleshooting](.claude/skills/troubleshooting/SKILL.md) | Debug common issues |

## Related

- [claude-code-remote](https://github.com/johnnymo87/claude-code-remote) - The notification relay system
- Worker deployed at: `https://ccr-router.jonathan-mohrbacher.workers.dev`
