// src/router-do.js
export class RouterDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    return new Response('RouterDO placeholder', { status: 200 });
  }
}
