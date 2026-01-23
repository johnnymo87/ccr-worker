// src/router-do.js
export class RouterDO {
  constructor(state, env) {
    this.state = state;
    this.ctx = state; // Alias for hibernation API
    this.env = env;
    this.sql = state.storage.sql;

    // Promise-based init guard (safe against JS interleaving)
    this.initPromise = null;

    // Limits to prevent DoS
    this.MAX_COMMAND_LENGTH = 10000;      // 10KB per command
    this.MAX_QUEUE_PER_MACHINE = 100;     // Max queued commands per machine
    this.MAX_SESSIONS = 1000;             // Max total sessions
  }

  // Get connected machine WebSocket by ID
  getMachineWebSocket(machineId) {
    const sockets = this.ctx.getWebSockets(machineId);
    return sockets.length > 0 ? sockets[0] : null;
  }

  // Get all connected machine IDs
  getConnectedMachines() {
    const allSockets = this.ctx.getWebSockets();
    const machines = new Set();
    for (const ws of allSockets) {
      const attachment = ws.deserializeAttachment();
      if (attachment?.machineId) {
        machines.add(attachment.machineId);
      }
    }
    return machines;
  }

  async ensureInitialized() {
    if (!this.initPromise) {
      this.initPromise = this._initializeOnce();
    }
    return this.initPromise;
  }

  async _initializeOnce() {
    // Use blockConcurrencyWhile for schema operations
    await this.state.blockConcurrencyWhile(async () => {
      await this._runSchemaSetup();

      // Schedule cleanup alarm if not already set
      const currentAlarm = await this.state.storage.getAlarm();
      if (!currentAlarm) {
        await this.state.storage.setAlarm(Date.now() + 60 * 60 * 1000);
        console.log('Cleanup alarm scheduled');
      }
    });
  }

  async _runSchemaSetup() {
    // Clean up any partial migration artifacts from crashed migrations
    const artifactTables = ['messages_new', 'command_queue_new'];
    for (const table of artifactTables) {
      try {
        const exists = this.sql.exec(`SELECT 1 FROM sqlite_master WHERE type='table' AND name=?`, table).toArray();
        if (exists.length > 0) {
          console.warn(`Cleaning up migration artifact: ${table}`);
          // Safe: table names come from hardcoded artifactTables array, not user input.
          // SQLite DDL (DROP TABLE) doesn't support parameterized table names, so string interpolation is required.
          this.sql.exec(`DROP TABLE IF EXISTS ${table}`);
        }
      } catch (e) {
        // Ignore errors checking for artifacts
      }
    }

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

    // Composite index for token+chat_id lookups (most common query pattern)
    this.sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_messages_token_chat ON messages(token, chat_id)
    `);

    // Index for command queue status queries
    this.sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_queue_machine_status ON command_queue(machine_id, status)
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

    // Validate chatId against allowlist (same as inbound)
    if (!this.isAllowedChatId(chatId)) {
      console.warn(`Outbound notification blocked: chatId ${chatId} not in allowlist`);
      return new Response(JSON.stringify({ error: 'Chat ID not allowed' }), {
        status: 403,
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
    const expected = this.env.TELEGRAM_WEBHOOK_SECRET;

    if (!secret || !expected) return false;
    if (secret.length !== expected.length) return false;

    // Constant-time comparison (same pattern as API key)
    const encoder = new TextEncoder();
    const a = encoder.encode(secret);
    const b = encoder.encode(expected);
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }

  isAllowedChatId(chatId) {
    const allowedChatsRaw = this.env.ALLOWED_CHAT_IDS || '';
    const allowedChats = allowedChatsRaw.split(',').map(id => id.trim()).filter(id => id.length > 0);

    if (allowedChats.length === 0) {
      return false;
    }

    return allowedChats.includes(String(chatId));
  }

  isAllowedTelegramSource(chatId, userId) {
    if (!this.isAllowedChatId(chatId)) {
      return false;
    }

    // User ID check (if configured)
    const allowedUsersRaw = this.env.ALLOWED_USER_IDS || '';
    const allowedUsers = allowedUsersRaw.split(',').map(id => id.trim()).filter(id => id.length > 0);

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

  // Verify API key from WebSocket subprotocol header
  verifyApiKeyFromProtocols(protocols) {
    const parts = protocols.split(',').map(p => p.trim());
    if (parts[0] !== 'ccr' || parts.length < 2) {
      return false;
    }

    const apiKey = parts[1];
    const expected = this.env.CCR_API_KEY;

    // Constant-time comparison
    if (!expected || apiKey.length !== expected.length) {
      return false;
    }

    const encoder = new TextEncoder();
    const a = encoder.encode(apiKey);
    const b = encoder.encode(expected);
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
    const chatId = callbackQuery.message?.chat?.id;
    const data = callbackQuery.data;

    // Guard: data can be undefined for some callback types
    if (typeof data !== 'string') {
      return new Response('ok', { status: 200 });
    }

    // Parse callback data (e.g., "cmd:TOKEN:continue")
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
    const ws = this.getMachineWebSocket(machineId);
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
    const RETRY_INTERVAL_MS = 60000; // Retry after 60s if not acked

    try {
      ws.send(JSON.stringify({
        type: 'command',
        commandId,
        sessionId,
        command,
        chatId: String(chatId)
      }));
      // Mark as sent, set retry time for if not acked
      this.sql.exec(`
        UPDATE command_queue
        SET status = 'sent', sent_at = ?, attempts = ?, next_retry_at = ?
        WHERE command_id = ?
      `, Date.now(), newAttempts, Date.now() + RETRY_INTERVAL_MS, commandId);
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

  async handleWebSocketUpgrade(request) {
    const url = new URL(request.url);
    const machineId = url.searchParams.get('machineId');

    // Validate machineId
    if (!machineId || typeof machineId !== 'string' ||
        machineId.length > 64 || !/^[a-zA-Z0-9-]+$/.test(machineId)) {
      return new Response('Invalid machine ID', { status: 400 });
    }

    // Auth via subprotocol
    const protocols = request.headers.get('Sec-WebSocket-Protocol');
    if (!protocols || !this.verifyApiKeyFromProtocols(protocols)) {
      return new Response('Unauthorized', { status: 401 });
    }

    // Close existing connection for this machine
    const existing = this.getMachineWebSocket(machineId);
    if (existing) {
      existing.close(4000, 'Replaced by new connection');
    }

    // Accept with hibernation API
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // Accept and attach machineId (survives hibernation)
    this.ctx.acceptWebSocket(server, [machineId]);
    server.serializeAttachment({ machineId });

    console.log(`Machine ${machineId} connected`);

    // Flush queued commands (fire-and-forget to not block upgrade response)
    this.flushCommandQueue(machineId, server).catch(err => {
      console.error(`Failed to flush queue for ${machineId}:`, err.message);
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { 'Sec-WebSocket-Protocol': 'ccr' }
    });
  }

  // Called by runtime when WebSocket receives message (hibernation API)
  async webSocketMessage(ws, message) {
    await this.ensureInitialized();

    // Size limit (handle both string and ArrayBuffer)
    const size = typeof message === 'string' ? message.length : message.byteLength;
    if (size > 65536) {
      console.warn('Oversized WebSocket message rejected');
      return;
    }

    const attachment = ws.deserializeAttachment();
    const machineId = attachment?.machineId;

    if (!machineId) {
      console.warn('WebSocket message from unknown machine');
      return;
    }

    try {
      const msg = JSON.parse(message);
      await this.handleMachineMessage(machineId, msg, ws);
    } catch (err) {
      console.error(`Error handling message from ${machineId}:`, err.message);
    }
  }

  // Called by runtime when WebSocket closes
  async webSocketClose(ws, code, reason, _wasClean) {
    await this.ensureInitialized();
    const attachment = ws.deserializeAttachment();
    const machineId = attachment?.machineId;
    console.log(`Machine ${machineId || 'unknown'} disconnected: ${code} ${reason}`);
  }

  // Called by runtime when WebSocket errors
  async webSocketError(ws, error) {
    await this.ensureInitialized();
    const attachment = ws.deserializeAttachment();
    const machineId = attachment?.machineId;
    console.error(`WebSocket error for ${machineId || 'unknown'}:`, error.message);
  }

  async flushCommandQueue(machineId, ws) {
    const BATCH_SIZE = 10;
    const MAX_INFLIGHT = 20;
    const now = Date.now();

    // Count inflight (sent but not acked)
    const inflight = this.sql.exec(`
      SELECT COUNT(*) as count FROM command_queue
      WHERE machine_id = ? AND status = 'sent'
    `, machineId).toArray()[0].count;

    if (inflight >= MAX_INFLIGHT) {
      console.log(`Inflight cap reached for ${machineId} (${inflight}/${MAX_INFLIGHT})`);
      return;
    }

    const toSend = Math.min(BATCH_SIZE, MAX_INFLIGHT - inflight);

    const commands = this.sql.exec(`
      SELECT command_id, session_id, command, chat_id
      FROM command_queue
      WHERE machine_id = ?
        AND status IN ('pending', 'sent')
        AND (next_retry_at IS NULL OR next_retry_at <= ?)
      ORDER BY created_at ASC
      LIMIT ?
    `, machineId, now, toSend).toArray();

    if (commands.length === 0) return;

    console.log(`Flushing ${commands.length} commands to ${machineId} (batch of ${toSend}, inflight: ${inflight})`);

    for (const cmd of commands) {
      this.sendCommand(ws, cmd.command_id, cmd.session_id, cmd.command, cmd.chat_id);
    }
  }

  async handleMachineMessage(machineId, msg, ws) {
    // Schema validation
    if (typeof msg !== 'object' || msg === null) {
      console.warn(`Invalid message from ${machineId}: not an object`);
      return;
    }

    const validTypes = ['ping', 'ack', 'commandResult'];
    if (!validTypes.includes(msg.type)) {
      console.warn(`Invalid message type from ${machineId}: ${msg.type}`);
      return;
    }

    if (msg.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong' }));
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
          // Flush more commands if any pending
          this.flushCommandQueue(machineId, ws).catch(err => {
            console.error(`Flush after ack failed: ${err.message}`);
          });
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

  async retrySentCommands() {
    const RETRY_AFTER_MS = 60000; // Retry sent commands not acked after 1 minute
    const MAX_ATTEMPTS = 10;
    const cutoff = Date.now() - RETRY_AFTER_MS;

    // Find sent commands that haven't been acked and are past retry window
    const stale = this.sql.exec(`
      SELECT command_id, machine_id, session_id, command, chat_id, attempts
      FROM command_queue
      WHERE status = 'sent'
        AND sent_at < ?
        AND attempts < ?
        AND (next_retry_at IS NULL OR next_retry_at <= ?)
      LIMIT 50
    `, cutoff, MAX_ATTEMPTS, Date.now()).toArray();

    if (stale.length === 0) return;

    console.log(`Retrying ${stale.length} stale sent commands`);

    for (const cmd of stale) {
      const ws = this.getMachineWebSocket(cmd.machine_id);
      if (ws && ws.readyState === 1) {
        this.sendCommand(ws, cmd.command_id, cmd.session_id, cmd.command, cmd.chat_id);
      } else {
        // Machine offline, mark for next retry with backoff
        const backoffMs = Math.min(1000 * Math.pow(2, cmd.attempts), 300000);
        this.sql.exec(`
          UPDATE command_queue SET next_retry_at = ? WHERE command_id = ?
        `, Date.now() + backoffMs, cmd.command_id);
      }
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

  async alarm() {
    await this.ensureInitialized();

    console.log('Alarm triggered - running cleanup and retry');
    await this.cleanup();
    await this.retrySentCommands();

    // Schedule next alarm
    await this.state.storage.setAlarm(Date.now() + 60 * 60 * 1000);
  }

  async fetch(request) {
    await this.ensureInitialized();

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
        return this.handleWebSocketUpgrade(request);
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
