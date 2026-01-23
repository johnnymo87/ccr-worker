// src/router-do.js
export class RouterDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;

    // WebSocket connections by machineId
    this.machines = new Map();

    // Limits to prevent DoS
    this.MAX_COMMAND_LENGTH = 10000;      // 10KB per command
    this.MAX_QUEUE_PER_MACHINE = 100;     // Max queued commands per machine
    this.MAX_SESSIONS = 1000;             // Max total sessions
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

    // Messages table migration: convert chat_id to TEXT for 64-bit precision
    const hasOldMessagesSchema = (() => {
      try {
        const cols = this.sql.exec(`PRAGMA table_info(messages)`).toArray();
        // Check if chat_id column type contains INT (old schema)
        // SQLite doesn't enforce types strictly, but we can check declared type
        const chatIdCol = cols.find(c => c.name === 'chat_id');
        // If table doesn't exist or chat_id not found, needs fresh creation
        return chatIdCol && chatIdCol.type.toUpperCase().includes('INT');
      } catch {
        return false;
      }
    })();

    if (hasOldMessagesSchema) {
      console.log('Migrating messages table for TEXT chat_id...');
      this.sql.exec(`
        CREATE TABLE messages_new (
          chat_id TEXT NOT NULL,
          message_id INTEGER NOT NULL,
          session_id TEXT NOT NULL,
          token TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          PRIMARY KEY (chat_id, message_id)
        )
      `);
      this.sql.exec(`
        INSERT INTO messages_new
        SELECT CAST(chat_id AS TEXT), message_id, session_id, token, created_at
        FROM messages
      `);
      this.sql.exec(`DROP TABLE messages`);
      this.sql.exec(`ALTER TABLE messages_new RENAME TO messages`);
      console.log('Messages migration complete');
    } else {
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS messages (
          chat_id TEXT NOT NULL,
          message_id INTEGER NOT NULL,
          session_id TEXT NOT NULL,
          token TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          PRIMARY KEY (chat_id, message_id)
        )
      `);
    }

    // Command queue migration: convert to command_id as PK with proper schema
    const hasOldSchema = (() => {
      try {
        const cols = this.sql.exec(`PRAGMA table_info(command_queue)`).toArray();
        const hasId = cols.some(c => c.name === 'id' && c.pk === 1);
        const hasCommandIdPK = cols.some(c => c.name === 'command_id' && c.pk === 1);
        return hasId && !hasCommandIdPK;
      } catch {
        return false;
      }
    })();

    if (hasOldSchema) {
      console.log('Migrating command_queue to new schema...');
      // Create new table with correct schema
      this.sql.exec(`
        CREATE TABLE command_queue_new (
          command_id TEXT PRIMARY KEY,
          machine_id TEXT NOT NULL,
          session_id TEXT NOT NULL,
          command TEXT NOT NULL,
          chat_id TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          created_at INTEGER NOT NULL,
          sent_at INTEGER,
          acked_at INTEGER,
          attempts INTEGER NOT NULL DEFAULT 0,
          next_retry_at INTEGER,
          last_error TEXT
        )
      `);
      // Copy existing data with generated command_id
      this.sql.exec(`
        INSERT INTO command_queue_new (command_id, machine_id, session_id, command, chat_id, status, created_at)
        SELECT 'legacy-' || id, machine_id, session_id, command, CAST(chat_id AS TEXT), 'pending', created_at
        FROM command_queue
      `);
      // Swap tables
      this.sql.exec(`DROP TABLE command_queue`);
      this.sql.exec(`ALTER TABLE command_queue_new RENAME TO command_queue`);
      console.log('Migration complete');
    } else {
      // Fresh install or already migrated
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS command_queue (
          command_id TEXT PRIMARY KEY,
          machine_id TEXT NOT NULL,
          session_id TEXT NOT NULL,
          command TEXT NOT NULL,
          chat_id TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          created_at INTEGER NOT NULL,
          sent_at INTEGER,
          acked_at INTEGER,
          attempts INTEGER NOT NULL DEFAULT 0,
          next_retry_at INTEGER,
          last_error TEXT
        )
      `);
    }

    // Backfill any NULL status values
    this.sql.exec(`UPDATE command_queue SET status = 'pending' WHERE status IS NULL`);

    // Seen updates: deduplicate Telegram webhook retries
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS seen_updates (
        update_id INTEGER PRIMARY KEY,
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
    this.sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_seen_updates_created ON seen_updates(created_at)
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

    // Check session limit (only count if this is a new session)
    const existing = this.sql.exec(
      `SELECT 1 FROM sessions WHERE session_id = ?`, sessionId
    ).toArray()[0];

    if (!existing) {
      const sessionCount = this.sql.exec(
        `SELECT COUNT(*) as count FROM sessions`
      ).toArray()[0].count;

      if (sessionCount >= this.MAX_SESSIONS) {
        return new Response(JSON.stringify({ error: 'Session limit reached' }), {
          status: 429,
          headers: { 'Content-Type': 'application/json' }
        });
      }
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

    // Touch session to prevent cleanup
    this.touchSession(sessionId);

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
          // Removed parse_mode: 'Markdown' - causes 502 on unescaped special chars
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
    `, String(chatId), messageId, sessionId, token, now);

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

  generateCommandId() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  touchSession(sessionId) {
    const now = Date.now();
    this.sql.exec(`
      UPDATE sessions SET updated_at = ? WHERE session_id = ?
    `, now, sessionId);
  }

  verifyWebhookSecret(request) {
    const secret = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
    return secret === this.env.TELEGRAM_WEBHOOK_SECRET;
  }

  isAllowedTelegramSource(chatId, userId) {
    // Parse ALLOWED_CHAT_IDS
    const allowedChatsRaw = this.env.ALLOWED_CHAT_IDS || '';
    const allowedChats = allowedChatsRaw
      .split(',')
      .map(id => id.trim())
      .filter(id => id.length > 0);

    // Fail closed: if no allowed chats configured, deny all
    if (allowedChats.length === 0) {
      console.warn('ALLOWED_CHAT_IDS not configured - denying all Telegram requests');
      return false;
    }

    // Check if chatId is allowed
    const chatIdStr = String(chatId);
    if (!allowedChats.includes(chatIdStr)) {
      return false;
    }

    // If ALLOWED_USER_IDS is configured, also check userId
    const allowedUsersRaw = this.env.ALLOWED_USER_IDS || '';
    const allowedUsers = allowedUsersRaw
      .split(',')
      .map(id => id.trim())
      .filter(id => id.length > 0);

    if (allowedUsers.length > 0) {
      const userIdStr = String(userId);
      if (!allowedUsers.includes(userIdStr)) {
        return false;
      }
    }

    return true;
  }

  verifyApiKey(request) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return false;
    }
    const token = authHeader.slice(7);
    const expected = this.env.CCR_API_KEY;

    // Constant-time comparison to prevent timing attacks
    if (!expected || token.length !== expected.length) {
      return false;
    }

    const encoder = new TextEncoder();
    const a = encoder.encode(token);
    const b = encoder.encode(expected);

    // crypto.subtle.timingSafeEqual is not available in Workers
    // Use manual constant-time comparison
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }

  async handleTelegramWebhook(request) {
    // Verify webhook secret
    if (!this.verifyWebhookSecret(request)) {
      console.warn('Invalid webhook secret');
      return new Response('Unauthorized', { status: 401 });
    }

    const update = await request.json();

    // Atomic deduplication: try to insert, check if it existed
    const updateId = update.update_id;
    if (updateId) {
      const insertResult = this.sql.exec(
        `INSERT OR IGNORE INTO seen_updates (update_id, created_at) VALUES (?, ?)`,
        updateId, Date.now()
      );

      // If rowsWritten is 0, the row already existed (duplicate)
      if (insertResult.rowsWritten === 0) {
        console.log(`Duplicate update ${updateId} ignored`);
        return new Response('ok', { status: 200 });
      }
    }

    console.log('Webhook received:', JSON.stringify(update).slice(0, 200));

    // Extract chatId and userId for allowlist check
    const chatId = update.message?.chat?.id || update.callback_query?.message?.chat?.id;
    const userId = update.message?.from?.id || update.callback_query?.from?.id;

    // Check allowlist
    if (!this.isAllowedTelegramSource(chatId, userId)) {
      console.warn(`Telegram request denied: chatId=${chatId}, userId=${userId}`);
      return new Response('ok', { status: 200 });
    }

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
      `, String(chatId), replyToMessage.message_id).toArray()[0];

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
        // Look up session by token (must match chat_id to prevent cross-chat replay)
        const mapping = this.sql.exec(`
          SELECT session_id FROM messages WHERE token = ? AND chat_id = ?
        `, token, String(chatId)).toArray()[0];
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

    // Look up session (must match chat_id to prevent cross-chat replay)
    const mapping = this.sql.exec(`
      SELECT session_id FROM messages WHERE token = ? AND chat_id = ?
    `, token, String(chatId)).toArray()[0];

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
    // Validate command length
    if (command.length > this.MAX_COMMAND_LENGTH) {
      await this.sendTelegramMessage(chatId,
        `Command too long (${command.length} chars, max ${this.MAX_COMMAND_LENGTH})`);
      return new Response('ok', { status: 200 });
    }

    const session = this.sql.exec(`
      SELECT machine_id, label FROM sessions WHERE session_id = ?
    `, sessionId).toArray()[0];

    if (!session) {
      await this.sendTelegramMessage(chatId, 'Session not found');
      return new Response('ok', { status: 200 });
    }

    this.touchSession(sessionId);
    const machineId = session.machine_id;

    // Check queue size (exclude acked)
    const queueSize = this.sql.exec(`
      SELECT COUNT(*) as count FROM command_queue WHERE machine_id = ? AND status != 'acked'
    `, machineId).toArray()[0].count;

    if (queueSize >= this.MAX_QUEUE_PER_MACHINE) {
      await this.sendTelegramMessage(chatId,
        `Queue full for ${session.label || machineId} (${queueSize} commands pending).`);
      return new Response('ok', { status: 200 });
    }

    // Generate immutable command ID
    const commandId = this.generateCommandId();
    const now = Date.now();

    // Always insert into queue first (durable) before any send attempt
    this.sql.exec(`
      INSERT INTO command_queue (command_id, machine_id, session_id, command, chat_id, status, created_at, next_retry_at)
      VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
    `, commandId, machineId, sessionId, command, String(chatId), now, now);

    // Try to send immediately if connected
    const ws = this.machines.get(machineId);
    if (ws && ws.readyState === 1) {
      this.sendCommand(ws, commandId, sessionId, command, chatId);
    } else {
      await this.sendTelegramMessage(chatId,
        `Command queued - ${session.label || machineId} is offline.`);
    }

    return new Response('ok', { status: 200 });
  }

  sendCommand(ws, commandId, sessionId, command, chatId) {
    const currentAttempts = this.getAttempts(commandId);
    const newAttempts = currentAttempts + 1;

    try {
      ws.send(JSON.stringify({
        type: 'command',
        commandId,
        sessionId,
        command,
        chatId: String(chatId)
      }));
      // Mark as sent, increment attempts
      this.sql.exec(`
        UPDATE command_queue
        SET status = 'sent', sent_at = ?, attempts = ?
        WHERE command_id = ?
      `, Date.now(), newAttempts, commandId);
      console.log(`Command ${commandId} sent (attempt ${newAttempts})`);
    } catch (err) {
      // Mark retry with exponential backoff
      const backoffMs = Math.min(1000 * Math.pow(2, currentAttempts), 300000); // max 5 min
      this.sql.exec(`
        UPDATE command_queue
        SET attempts = ?, next_retry_at = ?, last_error = ?
        WHERE command_id = ?
      `, newAttempts, Date.now() + backoffMs, err.message, commandId);
      console.error(`Failed to send command ${commandId}:`, err.message);
    }
  }

  getAttempts(commandId) {
    const row = this.sql.exec(`SELECT attempts FROM command_queue WHERE command_id = ?`, commandId).toArray()[0];
    return row ? row.attempts : 0;
  }

  async handleWebSocket(request) {
    const url = new URL(request.url);
    const machineId = url.searchParams.get('machineId');

    if (!machineId) {
      return new Response('machineId required', { status: 400 });
    }

    // Check auth via Sec-WebSocket-Protocol header
    // Client sends: Sec-WebSocket-Protocol: ccr, <api-key>
    const protocols = request.headers.get('Sec-WebSocket-Protocol');
    if (!protocols) {
      return new Response('Authentication required', { status: 401 });
    }

    const parts = protocols.split(',').map(p => p.trim());
    if (parts[0] !== 'ccr' || parts.length < 2) {
      return new Response('Invalid protocol', { status: 401 });
    }

    const apiKey = parts[1];
    const expected = this.env.CCR_API_KEY;

    // Constant-time comparison
    if (!expected || apiKey.length !== expected.length) {
      return new Response('Invalid API key', { status: 401 });
    }

    const encoder = new TextEncoder();
    const a = encoder.encode(apiKey);
    const b = encoder.encode(expected);
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    if (result !== 0) {
      return new Response('Invalid API key', { status: 401 });
    }

    // Auth passed - accept WebSocket
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // Close existing connection for this machine
    const existing = this.machines.get(machineId);
    if (existing && existing !== server) {
      existing.close(4000, 'Replaced by new connection');
    }

    this.machines.set(machineId, server);
    server.accept();

    console.log(`Machine authenticated and connected: ${machineId}`);

    // Flush queued commands (fire-and-forget, catch errors)
    this.flushCommandQueue(machineId, server).catch(err => {
      console.error(`Failed to flush queue for ${machineId}:`, err.message);
    });

    server.addEventListener('message', async (event) => {
      try {
        const msg = JSON.parse(event.data);
        await this.handleMachineMessage(machineId, msg);
      } catch (err) {
        console.error('Error handling machine message:', err);
      }
    });

    server.addEventListener('close', () => {
      console.log(`Machine disconnected: ${machineId}`);
      if (this.machines.get(machineId) === server) {
        this.machines.delete(machineId);
      }
    });

    server.addEventListener('error', (err) => {
      console.error(`WebSocket error for ${machineId}:`, err);
      if (this.machines.get(machineId) === server) {
        this.machines.delete(machineId);
      }
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: {
        'Sec-WebSocket-Protocol': 'ccr'
      }
    });
  }

  async flushCommandQueue(machineId, ws) {
    const BATCH_SIZE = 10;
    const now = Date.now();

    // Get pending/sent commands ready for (re)send, respecting backoff
    const commands = this.sql.exec(`
      SELECT command_id, session_id, command, chat_id
      FROM command_queue
      WHERE machine_id = ?
        AND status IN ('pending', 'sent')
        AND (next_retry_at IS NULL OR next_retry_at <= ?)
      ORDER BY created_at ASC
      LIMIT ?
    `, machineId, now, BATCH_SIZE).toArray();

    if (commands.length === 0) return;

    console.log(`Flushing ${commands.length} commands to ${machineId} (batch of ${BATCH_SIZE})`);

    for (const cmd of commands) {
      this.sendCommand(ws, cmd.command_id, cmd.session_id, cmd.command, cmd.chat_id);
    }
  }

  async handleMachineMessage(machineId, msg) {
    if (msg.type === 'ping') {
      const ws = this.machines.get(machineId);
      if (ws) ws.send(JSON.stringify({ type: 'pong' }));
      return;
    }

    if (msg.type === 'ack') {
      const { commandId } = msg;
      if (commandId && typeof commandId === 'string' && commandId.length <= 64) {
        // Validate this command belongs to this machine (prevents cross-machine deletion)
        const result = this.sql.exec(`
          UPDATE command_queue SET status = 'acked', acked_at = ?
          WHERE command_id = ? AND machine_id = ?
        `, Date.now(), commandId, machineId);
        if (result.rowsWritten > 0) {
          console.log(`Command ${commandId} acked by ${machineId}`);
        }
      }
      return;
    }

    if (msg.type === 'commandResult') {
      const { success, error, chatId } = msg;
      if (!success && chatId) {
        await this.sendTelegramMessage(chatId, `Command failed: ${error}`);
      }
      return;
    }
  }

  async cleanup() {
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
    const oneHourAgo = Date.now() - 60 * 60 * 1000;

    // Clean old messages
    const msgCursor = this.sql.exec(`
      DELETE FROM messages WHERE created_at < ?
    `, oneDayAgo);

    // Clean acked commands older than 1 hour (keep briefly for debugging)
    const queueCleanup = this.sql.exec(`
      DELETE FROM command_queue WHERE status = 'acked' AND acked_at < ?
    `, oneHourAgo);
    console.log(`Cleaned ${queueCleanup.rowsWritten} acked commands`);

    // Clean stuck pending/sent commands older than 24h (failed delivery)
    const stuckCleanup = this.sql.exec(`
      DELETE FROM command_queue WHERE status != 'acked' AND created_at < ?
    `, oneDayAgo);
    console.log(`Cleaned ${stuckCleanup.rowsWritten} stuck commands`);

    // Clean stale sessions (no activity in 24h)
    const sessionCursor = this.sql.exec(`
      DELETE FROM sessions WHERE updated_at < ?
    `, oneDayAgo);

    // Clean old seen updates (keep 1 hour worth)
    const seenCursor = this.sql.exec(`
      DELETE FROM seen_updates WHERE created_at < ?
    `, oneHourAgo);

    console.log(`Cleanup: ${msgCursor.rowsWritten} messages, ${sessionCursor.rowsWritten} sessions, ${seenCursor.rowsWritten} seen_updates`);
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
