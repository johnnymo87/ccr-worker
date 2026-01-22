// src/router-do.js
export class RouterDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;

    // WebSocket connections by machineId
    this.machines = new Map();
  }

  async initialize() {
    // Sessions: which machine owns which session
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        machine_id TEXT NOT NULL,
        label TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);

    // Messages: map Telegram message_id to session for reply routing
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        chat_id INTEGER NOT NULL,
        message_id INTEGER NOT NULL,
        session_id TEXT NOT NULL,
        token TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (chat_id, message_id)
      )
    `);

    // Command queue: pending commands for offline machines
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS command_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        machine_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        command TEXT NOT NULL,
        chat_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      )
    `);

    // Indexes
    this.sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_sessions_machine ON sessions(machine_id)
    `);
    this.sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_queue_machine ON command_queue(machine_id)
    `);
    this.sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)
    `);
  }

  async handleRegisterSession(body) {
    const { sessionId, machineId, label } = body;

    if (!sessionId || !machineId) {
      return new Response(JSON.stringify({ error: 'sessionId and machineId required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const now = Date.now();

    this.sql.exec(`
      INSERT INTO sessions (session_id, machine_id, label, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(session_id) DO UPDATE SET
        machine_id = excluded.machine_id,
        label = excluded.label,
        updated_at = excluded.updated_at
    `, sessionId, machineId, label || null, now, now);

    console.log(`Session registered: ${sessionId} → ${machineId} (${label || 'no label'})`);

    return new Response(JSON.stringify({ ok: true, sessionId, machineId }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async handleUnregisterSession(body) {
    const { sessionId } = body;

    if (!sessionId) {
      return new Response(JSON.stringify({ error: 'sessionId required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    this.sql.exec(`DELETE FROM sessions WHERE session_id = ?`, sessionId);
    this.sql.exec(`DELETE FROM messages WHERE session_id = ?`, sessionId);

    console.log(`Session unregistered: ${sessionId}`);

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async handleSendNotification(body) {
    const { sessionId, chatId, text, replyMarkup } = body;

    if (!sessionId || !chatId || !text) {
      return new Response(JSON.stringify({ error: 'sessionId, chatId, and text required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Get session to verify it exists
    const session = this.sql.exec(
      `SELECT * FROM sessions WHERE session_id = ?`, sessionId
    ).toArray()[0];

    if (!session) {
      return new Response(JSON.stringify({ error: 'Session not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Generate token for this notification
    const token = this.generateToken();

    // Send to Telegram
    const telegramResponse = await fetch(
      `https://api.telegram.org/bot${this.env.TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text: text,
          parse_mode: 'Markdown',
          reply_markup: replyMarkup || undefined
        })
      }
    );

    const telegramResult = await telegramResponse.json();

    if (!telegramResult.ok) {
      console.error('Telegram error:', telegramResult);
      return new Response(JSON.stringify({ error: 'Telegram API error', details: telegramResult }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const messageId = telegramResult.result.message_id;

    // Store message → session mapping for reply routing
    const now = Date.now();
    this.sql.exec(`
      INSERT INTO messages (chat_id, message_id, session_id, token, created_at)
      VALUES (?, ?, ?, ?, ?)
    `, chatId, messageId, sessionId, token, now);

    console.log(`Notification sent: msg ${messageId} → session ${sessionId}`);

    return new Response(JSON.stringify({
      ok: true,
      messageId,
      token
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  generateToken() {
    const bytes = new Uint8Array(12);
    crypto.getRandomValues(bytes);
    return btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  verifyWebhookSecret(request) {
    const secret = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
    return secret === this.env.TELEGRAM_WEBHOOK_SECRET;
  }

  verifyApiKey(request) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return false;
    }
    const token = authHeader.slice(7);
    return token === this.env.CCR_API_KEY;
  }

  async handleTelegramWebhook(request) {
    // Verify webhook secret
    if (!this.verifyWebhookSecret(request)) {
      console.warn('Invalid webhook secret');
      return new Response('Unauthorized', { status: 401 });
    }

    const update = await request.json();
    console.log('Webhook received:', JSON.stringify(update).slice(0, 200));

    // Handle message (including replies)
    if (update.message) {
      return this.handleTelegramMessage(update.message);
    }

    // Handle callback query (button clicks)
    if (update.callback_query) {
      return this.handleTelegramCallback(update.callback_query);
    }

    // Acknowledge other update types
    return new Response('ok', { status: 200 });
  }

  async handleTelegramMessage(message) {
    const chatId = message.chat.id;
    const text = message.text || '';
    const replyToMessage = message.reply_to_message;

    // Try to route via reply-to-message
    let sessionId = null;
    let token = null;

    if (replyToMessage) {
      const mapping = this.sql.exec(`
        SELECT session_id, token FROM messages
        WHERE chat_id = ? AND message_id = ?
      `, chatId, replyToMessage.message_id).toArray()[0];

      if (mapping) {
        sessionId = mapping.session_id;
        token = mapping.token;
      }
    }

    // If no reply-to match, try parsing /cmd TOKEN format
    if (!sessionId) {
      const cmdMatch = text.match(/^\/cmd\s+(\S+)\s+(.+)$/s);
      if (cmdMatch) {
        token = cmdMatch[1];
        // Look up session by token
        const mapping = this.sql.exec(`
          SELECT session_id FROM messages WHERE token = ?
        `, token).toArray()[0];
        if (mapping) {
          sessionId = mapping.session_id;
        }
      }
    }

    if (!sessionId) {
      // Can't route - send error
      await this.sendTelegramMessage(chatId,
        '⏰ Could not find session for this message. Please reply to a recent notification or use /cmd TOKEN command format.');
      return new Response('ok', { status: 200 });
    }

    // Get the command text
    let command = text;
    if (text.startsWith('/cmd')) {
      command = text.replace(/^\/cmd\s+\S+\s+/, '');
    }

    // Route command to machine
    return this.routeCommandToMachine(sessionId, command, chatId);
  }

  async handleTelegramCallback(callbackQuery) {
    const chatId = callbackQuery.message?.chat.id;
    const messageId = callbackQuery.message?.message_id;
    const data = callbackQuery.data; // e.g., "cmd:TOKEN:continue"

    // Parse callback data
    const parts = data.split(':');
    if (parts[0] !== 'cmd' || parts.length < 3) {
      return new Response('ok', { status: 200 });
    }

    const token = parts[1];
    const action = parts.slice(2).join(':');

    // Look up session
    const mapping = this.sql.exec(`
      SELECT session_id FROM messages WHERE token = ?
    `, token).toArray()[0];

    if (!mapping) {
      await this.answerCallbackQuery(callbackQuery.id, 'Session expired');
      return new Response('ok', { status: 200 });
    }

    // Map action to command
    const commandMap = {
      'continue': '',
      'yes': 'y',
      'no': 'n',
      'exit': '/exit'
    };

    const command = commandMap[action] ?? action;

    // Acknowledge the button press
    await this.answerCallbackQuery(callbackQuery.id, `Sending: ${command || '(continue)'}`);

    // Route to machine
    return this.routeCommandToMachine(mapping.session_id, command, chatId);
  }

  async sendTelegramMessage(chatId, text) {
    await fetch(`https://api.telegram.org/bot${this.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text })
    });
  }

  async answerCallbackQuery(callbackQueryId, text) {
    await fetch(`https://api.telegram.org/bot${this.env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ callback_query_id: callbackQueryId, text })
    });
  }

  async routeCommandToMachine(sessionId, command, chatId) {
    // Get machine for this session
    const session = this.sql.exec(`
      SELECT machine_id, label FROM sessions WHERE session_id = ?
    `, sessionId).toArray()[0];

    if (!session) {
      await this.sendTelegramMessage(chatId, '❌ Session not found');
      return new Response('ok', { status: 200 });
    }

    const machineId = session.machine_id;

    // Check if machine is connected via WebSocket
    const ws = this.machines.get(machineId);

    if (ws && ws.readyState === 1) { // WebSocket.OPEN
      // Send command over WebSocket
      ws.send(JSON.stringify({
        type: 'command',
        sessionId,
        command,
        chatId
      }));

      console.log(`Command sent to ${machineId}: ${command.slice(0, 50)}`);
      return new Response('ok', { status: 200 });
    }

    // Machine offline - queue command
    const now = Date.now();
    this.sql.exec(`
      INSERT INTO command_queue (machine_id, session_id, command, chat_id, created_at)
      VALUES (?, ?, ?, ?, ?)
    `, machineId, sessionId, command, chatId, now);

    await this.sendTelegramMessage(chatId,
      `📥 Command queued - ${session.label || machineId} is offline. Will deliver when it reconnects.`);

    return new Response('ok', { status: 200 });
  }

  async handleWebSocket(request) {
    const url = new URL(request.url);
    const machineId = url.searchParams.get('machineId');

    if (!machineId) {
      return new Response('machineId required', { status: 400 });
    }

    // Accept WebSocket upgrade
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    server.accept();

    let authenticated = false;

    // Set up 10-second auth timeout
    const authTimeout = setTimeout(() => {
      if (!authenticated) {
        console.warn(`Auth timeout for ${machineId}`);
        server.close(4001, 'Auth timeout');
      }
    }, 10000);

    server.addEventListener('message', async (event) => {
      try {
        const msg = JSON.parse(event.data);

        // First message must be auth
        if (!authenticated) {
          clearTimeout(authTimeout);

          if (msg.type !== 'auth') {
            console.warn(`First message not auth for ${machineId}`);
            server.close(4002, 'First message must be auth');
            return;
          }

          if (msg.apiKey !== this.env.CCR_API_KEY) {
            console.warn(`Invalid API key for ${machineId}`);
            server.close(4003, 'Invalid API key');
            return;
          }

          // Auth successful - close existing connection for same machineId if any
          const existing = this.machines.get(machineId);
          if (existing && existing !== server) {
            console.log(`Closing existing connection for ${machineId}`);
            existing.close(4000, 'Replaced by new connection');
          }

          // Now add to machines map
          authenticated = true;
          this.machines.set(machineId, server);
          server.send(JSON.stringify({ type: 'authSuccess' }));
          console.log(`Machine authenticated: ${machineId}`);

          // Send queued commands
          this.flushCommandQueue(machineId, server);
          return;
        }

        // Authenticated - handle normal messages
        await this.handleMachineMessage(machineId, msg);
      } catch (err) {
        console.error('Error handling machine message:', err);
      }
    });

    server.addEventListener('close', () => {
      clearTimeout(authTimeout);
      console.log(`Machine disconnected: ${machineId}`);
      // Only delete if this is still the current connection for this machineId
      if (this.machines.get(machineId) === server) {
        this.machines.delete(machineId);
      }
    });

    server.addEventListener('error', (err) => {
      clearTimeout(authTimeout);
      console.error(`WebSocket error for ${machineId}:`, err);
      // Only delete if this is still the current connection for this machineId
      if (this.machines.get(machineId) === server) {
        this.machines.delete(machineId);
      }
    });

    return new Response(null, {
      status: 101,
      webSocket: client
    });
  }

  async flushCommandQueue(machineId, ws) {
    const commands = this.sql.exec(`
      SELECT id, session_id, command, chat_id
      FROM command_queue
      WHERE machine_id = ?
      ORDER BY created_at ASC
    `, machineId).toArray();

    if (commands.length === 0) return;

    console.log(`Flushing ${commands.length} queued commands to ${machineId}`);

    for (const cmd of commands) {
      ws.send(JSON.stringify({
        type: 'command',
        sessionId: cmd.session_id,
        command: cmd.command,
        chatId: cmd.chat_id
      }));

      // Delete from queue
      this.sql.exec(`DELETE FROM command_queue WHERE id = ?`, cmd.id);
    }
  }

  async handleMachineMessage(machineId, msg) {
    // Handle messages from machine agents
    if (msg.type === 'ping') {
      const ws = this.machines.get(machineId);
      if (ws) ws.send(JSON.stringify({ type: 'pong' }));
      return;
    }

    if (msg.type === 'commandResult') {
      // Machine reporting command execution result
      const { sessionId, success, error, chatId } = msg;

      if (!success && chatId) {
        await this.sendTelegramMessage(chatId, `❌ Command failed: ${error}`);
      }
      return;
    }

    console.log(`Unknown message from ${machineId}:`, msg);
  }

  async cleanup() {
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;

    // Clean old messages
    const msgResult = this.sql.exec(`
      DELETE FROM messages WHERE created_at < ?
    `, oneDayAgo);

    // Clean old queued commands (shouldn't happen if machines reconnect)
    const queueResult = this.sql.exec(`
      DELETE FROM command_queue WHERE created_at < ?
    `, oneDayAgo);

    // Clean stale sessions (no activity in 24h)
    const sessionResult = this.sql.exec(`
      DELETE FROM sessions WHERE updated_at < ?
    `, oneDayAgo);

    console.log(`Cleanup: ${msgResult.changes} messages, ${queueResult.changes} queued, ${sessionResult.changes} sessions`);
  }

  async fetch(request) {
    await this.initialize();

    const url = new URL(request.url);
    const path = url.pathname;

    // Routes that require API key authentication
    const protectedRoutes = [
      '/sessions/register',
      '/sessions/unregister',
      '/sessions',
      '/notifications/send',
      '/cleanup'
    ];

    const needsAuth = protectedRoutes.some(route => path === route || path.startsWith(route + '/'));

    if (needsAuth && !this.verifyApiKey(request)) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      // WebSocket upgrade for machine agents
      if (path === '/ws' && request.headers.get('Upgrade') === 'websocket') {
        return this.handleWebSocket(request);
      }

      // Session management
      if (path === '/sessions/register' && request.method === 'POST') {
        const body = await request.json();
        return this.handleRegisterSession(body);
      }

      if (path === '/sessions/unregister' && request.method === 'POST') {
        const body = await request.json();
        return this.handleUnregisterSession(body);
      }

      // List sessions (for debugging)
      if (path === '/sessions' && request.method === 'GET') {
        const rows = this.sql.exec(`SELECT * FROM sessions`).toArray();
        return new Response(JSON.stringify(rows), {
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // Notification sending (proxied through Worker)
      if (path === '/notifications/send' && request.method === 'POST') {
        const body = await request.json();
        return this.handleSendNotification(body);
      }

      // Telegram webhook
      if (path.startsWith('/webhook/telegram') && request.method === 'POST') {
        return this.handleTelegramWebhook(request);
      }

      // Cleanup (call periodically via cron or manually)
      if (path === '/cleanup' && request.method === 'POST') {
        await this.cleanup();
        return new Response(JSON.stringify({ ok: true }), {
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return new Response('Not found', { status: 404 });

    } catch (err) {
      console.error('Error:', err);
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
}
