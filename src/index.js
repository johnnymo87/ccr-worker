// src/index.js
export { RouterDO } from './router-do.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/health') {
      return new Response('ok', { status: 200 });
    }

    // All other requests go to the Durable Object
    const id = env.ROUTER.idFromName('global');
    const stub = env.ROUTER.get(id);
    return stub.fetch(request);
  }
};
