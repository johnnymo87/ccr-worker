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

  async fetch(request) {
    // Ensure tables exist
    await this.initialize();

    return new Response('RouterDO initialized', { status: 200 });
  }
}
