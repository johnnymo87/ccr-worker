---
name: architecture
description: Use when you need to understand how the CCR Worker routes messages, manages sessions, or handles WebSocket connections
---

# CCR Worker Architecture

## Overview

The CCR Worker is a Cloudflare Worker that routes Telegram messages to the correct Claude Code Remote instance across multiple machines. It uses a Durable Object for persistent state.

## System Flow

```
┌──────────────┐      ┌─────────────────────────────────────┐
│   Telegram   │      │         Cloudflare Worker           │
│              │      │                                     │
│  User sends  │─────▶│  POST /webhook/telegram/{secret}    │
│   message    │      │              │                      │
└──────────────┘      │              ▼                      │
                      │    ┌─────────────────────┐          │
                      │    │   RouterDO (DO)     │          │
                      │    │                     │          │
                      │    │ • SQLite session DB │          │
                      │    │ • message→session   │          │
                      │    │ • session→machine   │          │
                      │    │ • command queue     │          │
                      │    └──────────┬──────────┘          │
                      │               │                     │
                      │               ▼                     │
                      │    WebSocket to Machine Agent       │
                      └───────────────┬─────────────────────┘
                                      │
                      ┌───────────────▼───────────────┐
                      │   Machine (devbox/macbook)    │
                      │                               │
                      │   MachineAgent ◄── WebSocket  │
                      │        │                      │
                      │        ▼                      │
                      │   Inject into Claude session  │
                      └───────────────────────────────┘
```

## Components

### Worker Entry Point (`src/index.js`)

Routes HTTP requests:
- `/webhook/telegram/{secret}` → Telegram webhook handler
- `/ws?machineId=X` → WebSocket upgrade for machine agents
- `/sessions/*` → Session management API
- `/notifications/send` → Outbound notification API
- `/health` → Health check

### Durable Object (`src/router-do.js`)

Single instance that manages all state:

**SQLite Tables:**
- `sessions` - Maps session_id → machine_id
- `messages` - Maps Telegram message_id → session_id (for reply routing)
- `command_queue` - Pending commands with retry logic
- `seen_updates` - Deduplication for Telegram webhooks

**WebSocket Handling:**
- Machine agents connect via `/ws?machineId=X`
- Uses WebSocket Hibernation API for cost efficiency
- Auto-reconnects handled by MachineAgent client

**Command Flow:**
1. Telegram webhook arrives with reply to notification
2. Look up `message_id` → `session_id` in `messages` table
3. Look up `session_id` → `machine_id` in `sessions` table
4. Queue command in `command_queue`
5. Send via WebSocket to connected machine
6. Wait for ack, retry if needed

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | None | Returns "ok" |
| `/sessions` | GET | API Key | List all sessions |
| `/sessions/register` | POST | API Key | Register session→machine mapping |
| `/sessions/unregister` | POST | API Key | Remove session |
| `/notifications/send` | POST | API Key | Send notification, store message mapping |
| `/webhook/telegram/{secret}` | POST | Path secret | Telegram webhook receiver |
| `/ws` | WebSocket | API Key (subprotocol) | Machine agent connection |

## Authentication

- **API Key**: Passed in `X-API-Key` header or WebSocket subprotocol
- **Webhook Secret**: Telegram's `X-Telegram-Bot-Api-Secret-Token` header
- **Path Secret**: URL path component for webhook endpoint

## Message Delivery Guarantees

**At-least-once delivery:**
- Commands persisted to `command_queue` before send attempt
- Retry sweep runs hourly for unacked commands
- Exponential backoff on failures
- Dead letter after 24h

**Duplicate handling:**
- `seen_updates` table prevents replay of Telegram webhooks
- MachineAgent inbox prevents duplicate command execution

## Environment Variables

| Variable | Source | Description |
|----------|--------|-------------|
| `TELEGRAM_BOT_TOKEN` | Secret | Bot token for sending messages |
| `TELEGRAM_WEBHOOK_SECRET` | Secret | Validates Telegram webhooks |
| `CCR_API_KEY` | Secret | Authenticates machine agents |
| `ALLOWED_CHAT_IDS` | Var | Comma-separated allowed Telegram chats |

## Deployment

See [deployment skill](.claude/skills/deployment/SKILL.md).

## Related

- [claude-code-remote](https://github.com/johnnymo87/claude-code-remote) - Machine agent and webhook server
- [Cloudflare Durable Objects](https://developers.cloudflare.com/durable-objects/)
- [WebSocket Hibernation API](https://developers.cloudflare.com/durable-objects/api/websockets/)
