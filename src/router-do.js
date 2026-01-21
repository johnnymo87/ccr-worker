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

  async fetch(request) {
    await this.initialize();

    const url = new URL(request.url);
    const path = url.pathname;

    try {
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
