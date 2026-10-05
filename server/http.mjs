import { createServer } from 'node:http';
import { timingSafeEqual, createHash } from 'node:crypto';

const BODY_LIMIT = 16 * 1024 * 1024;
const digest = value => createHash('sha256').update(value).digest();
const authorized = (header, token) => typeof header === 'string' && header.startsWith('Bearer ') && timingSafeEqual(digest(header.slice(7)), digest(token));
export function createThreatServer(store, { adminToken = store.token() } = {}) {
  if (adminToken.length < 32) throw new Error('Admin token must have at least 32 characters.');
  const server = createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    const send = (status, body, type = 'application/json') => { res.writeHead(status, { 'Content-Type': type }); res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body)); };
    try {
      // No CORS; browser pages cannot mutate the server with cross-origin JSON requests.
      if (req.headers.origin) return send(403, { error: 'Browser-origin requests are not accepted.' });
      if (req.url === '/healthz' && req.method === 'GET') return send(200, store.health());
      if (req.url === '/v1/feed' && req.method === 'GET') return send(200, store.feed());
      if (req.url === '/v1/public-key' && req.method === 'GET') return send(200, store.publicKey(), 'text/plain');
      if (req.url?.startsWith('/v1/admin/')) {
        if (!authorized(req.headers.authorization, adminToken)) return send(401, { error: 'Authentication required.' });
        if (req.method !== 'POST') return send(405, { error: 'POST required.' });
        if (!req.headers['content-type']?.startsWith('application/json')) return send(415, { error: 'JSON required.' });
        if (Number(req.headers['content-length']) > BODY_LIMIT) return send(413, { error: 'Request too large.' });
        const buffers = []; let size = 0;
        for await (const chunk of req) { size += chunk.length; if (size > BODY_LIMIT) { send(413, { error: 'Request too large.' }); req.destroy(); return; } buffers.push(chunk); }
        let body;
        try { body = JSON.parse(Buffer.concat(buffers)); } catch { return send(400, { error: 'Invalid JSON.' }); }
        if (req.url === '/v1/admin/import') return send(200, store.import(body.hashes, 'Operator curated'));
        if (req.url === '/v1/admin/allow') return send(200, store.allow(body.sha256));
        if (req.url === '/v1/admin/remove') return send(200, store.remove(body.sha256));
        if (req.url === '/v1/admin/publish') return send(200, store.publish());
      }
      return send(404, { error: 'Not found.' });
    } catch (error) {
      // Operational errors do not echo uploaded bodies, auth tokens or private keys.
      send(error.message?.startsWith('Invalid') || error.message?.startsWith('Expected') ? 400 : 500, { error: 'Operation failed. Check server state and the documented request format.' });
    }
  });
  server.requestTimeout = 30_000; server.headersTimeout = 15_000; server.keepAliveTimeout = 5_000; server.maxHeadersCount = 40; server.maxConnections = 128;
  return server;
}
