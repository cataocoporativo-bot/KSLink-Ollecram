// KSLink 2.0 — servidor de sinalização.
//
// O que este servidor FAZ:
//   • serve os arquivos estáticos do app (public/);
//   • mantém salas efêmeras em memória e repassa mensagens de sinalização
//     WebRTC (SDP/ICE) entre os participantes de uma mesma sala;
//   • exige prova de posse da chave de identidade (ECDSA P-256) no "join".
//
// O que este servidor NÃO faz:
//   • não vê, não armazena e não registra o conteúdo das conversas ou arquivos
//     (eles trafegam direto entre os navegadores, cifrados de ponta a ponta);
//   • não grava nada em disco nem registra IPs, nomes ou identidades.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import { WebSocketServer } from 'ws';

const here = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(here, '..', 'public');
const subtle = globalThis.crypto.subtle;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};

const DEFAULT_ICE = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data: blob:",
  "connect-src 'self' ws: wss: https:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

const JOIN_TIMEOUT_MS = 10_000;
const HEARTBEAT_MS = 30_000;
const RATE_BURST = 400; // mensagens
const RATE_PER_SEC = 50; // reposição por segundo
const MAX_PAYLOAD = 64 * 1024;

function envInt(v, d) {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : d;
}

export function loadConfig(env = process.env, overrides = {}) {
  let iceServers = DEFAULT_ICE;
  if (env.ICE_SERVERS) {
    try {
      const parsed = JSON.parse(env.ICE_SERVERS);
      if (Array.isArray(parsed)) iceServers = parsed;
    } catch {
      console.warn('ICE_SERVERS inválido (JSON esperado); usando STUN padrão.');
    }
  }
  return {
    port: envInt(env.PORT, 8080),
    host: env.HOST || '0.0.0.0',
    maxPeers: envInt(env.MAX_PEERS, 8),
    maxRooms: envInt(env.MAX_ROOMS, 5000),
    maxConnections: envInt(env.MAX_CONNECTIONS, 5000),
    maxConnPerIp: envInt(env.MAX_CONN_PER_IP, 30),
    trustProxy: env.TRUST_PROXY === '1',
    allowedOrigins: (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean),
    iceServers,
    ...overrides,
  };
}

const isRoomId = (s) => typeof s === 'string' && /^[A-Za-z0-9_-]{6,64}$/.test(s);
const cleanName = (s) =>
  typeof s === 'string' ? s.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 32) : '';

export function createApp(cfg = loadConfig()) {
  const rooms = new Map(); // roomId -> Map(sid -> conn)
  const ipCount = new Map();
  let connCount = 0;

  // ───────────────────────── HTTP ─────────────────────────
  function originAllowed(req) {
    const origin = req.headers.origin;
    if (!origin) return true; // clientes que não são navegador (testes, curl)
    if (cfg.allowedOrigins.includes('*') || cfg.allowedOrigins.includes(origin)) return true;
    try {
      return new URL(origin).host === req.headers.host; // mesma origem
    } catch {
      return false;
    }
  }

  function clientIp(req) {
    if (cfg.trustProxy) {
      const xf = req.headers['x-forwarded-for'];
      if (typeof xf === 'string' && xf) return xf.split(',')[0].trim();
    }
    return req.socket.remoteAddress ?? 'unknown';
  }

  function securityHeaders(req, res) {
    res.setHeader('Content-Security-Policy', CSP);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    if (cfg.trustProxy && req.headers['x-forwarded-proto'] === 'https') {
      res.setHeader('Strict-Transport-Security', 'max-age=15552000');
    }
  }

  function serveStatic(pathname, req, res) {
    let rel;
    try {
      rel = decodeURIComponent(pathname);
    } catch {
      res.writeHead(400);
      return res.end();
    }
    if (rel.includes('\0')) {
      res.writeHead(400);
      return res.end();
    }
    if (rel === '/') rel = '/index.html';
    const full = path.resolve(PUBLIC_DIR, '.' + rel);
    if (full !== PUBLIC_DIR && !full.startsWith(PUBLIC_DIR + path.sep)) {
      res.writeHead(403);
      return res.end();
    }
    fs.stat(full, (err, st) => {
      const type = MIME[path.extname(full).toLowerCase()];
      if (err || !st.isFile() || !type) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        return res.end('não encontrado');
      }
      res.writeHead(200, {
        'content-type': type,
        'content-length': st.size,
        'cache-control': rel.startsWith('/fonts/') ? 'public, max-age=31536000, immutable' : 'no-cache',
      });
      if (req.method === 'HEAD') return res.end();
      const stream = fs.createReadStream(full);
      stream.on('error', () => res.destroy());
      stream.pipe(res);
    });
  }

  function handleIce(req, res) {
    const headers = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
    const origin = req.headers.origin;
    if (origin) {
      if (!originAllowed(req)) {
        res.writeHead(403);
        return res.end();
      }
      headers['access-control-allow-origin'] = origin;
      headers.vary = 'Origin';
    }
    res.writeHead(200, headers);
    res.end(JSON.stringify({ iceServers: cfg.iceServers }));
  }

  const server = http.createServer((req, res) => {
    securityHeaders(req, res);
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end('ok');
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' });
      return res.end();
    }
    if (url.pathname === '/ice') return handleIce(req, res);
    serveStatic(url.pathname, req, res);
  });

  // ──────────────────────── WebSocket ─────────────────────
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_PAYLOAD });

  server.on('upgrade', (req, socket, head) => {
    const reject = (code, msg) => {
      socket.write(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\n\r\n`);
      socket.destroy();
    };
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/ws') return reject(404, 'Not Found');
    if (!originAllowed(req)) return reject(403, 'Forbidden');
    const ip = clientIp(req);
    if (connCount >= cfg.maxConnections || (ipCount.get(ip) ?? 0) >= cfg.maxConnPerIp) {
      return reject(429, 'Too Many Requests');
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req, ip));
  });

  const send = (ws, obj) => {
    if (ws.readyState === 1) ws.send(JSON.stringify(obj));
  };
  const info = (c) => ({ sid: c.sid, fp: c.fp, name: c.name });

  function takeToken(c) {
    const now = Date.now();
    c.tokens = Math.min(RATE_BURST, c.tokens + ((now - c.last) / 1000) * RATE_PER_SEC);
    c.last = now;
    if (c.tokens < 1) return false;
    c.tokens -= 1;
    return true;
  }

  function fail(conn, code) {
    conn.joining = false;
    send(conn.ws, { t: 'error', code });
    conn.ws.close(4000, code);
  }

  async function onJoin(conn, m) {
    if (conn.room || conn.joining) return fail(conn, 'already_joined');
    conn.joining = true;
    const { room, sid, pub, sig } = m;
    if (
      !isRoomId(room) ||
      !/^[0-9a-f]{16}$/.test(sid ?? '') ||
      !/^[0-9a-f]{130}$/.test(pub ?? '') ||
      !/^[0-9a-f]{128}$/.test(sig ?? '')
    ) {
      return fail(conn, 'bad_request');
    }
    const pubBytes = Buffer.from(pub, 'hex');
    let ok = false;
    try {
      const key = await subtle.importKey('raw', pubBytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      ok = await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        Buffer.from(sig, 'hex'),
        Buffer.from(`KSLINK-JOIN|v2|${conn.nonce}|${room}|${sid}`),
      );
    } catch {
      ok = false;
    }
    if (!ok) return fail(conn, 'bad_signature');
    if (conn.ws.readyState !== 1) return; // fechou durante a verificação

    let members = rooms.get(room);
    if (!members) {
      if (rooms.size >= cfg.maxRooms) return fail(conn, 'server_busy');
      members = new Map();
      rooms.set(room, members);
    }
    const fp = createHash('sha256').update(pubBytes).digest('hex');
    const stale = members.get(sid);
    if (stale) {
      // Reconexão após queda de rede: o socket antigo ainda está "vivo" para o servidor.
      // Quem prova ser a mesma identidade (assinatura válida) assume a sessão.
      if (stale.fp !== fp) return fail(conn, 'sid_in_use');
      leaveRoom(stale);
      try { stale.ws.close(4001, 'replaced'); } catch { /* já fechado */ }
      rooms.set(room, members); // leaveRoom pode ter removido a sala vazia
    }
    if (members.size >= cfg.maxPeers) return fail(conn, 'room_full');

    conn.room = room;
    conn.sid = sid;
    conn.fp = fp;
    conn.name = cleanName(m.name);
    const existing = [...members.values()].map(info);
    members.set(sid, conn);
    send(conn.ws, { t: 'joined', sid, fp: conn.fp, peers: existing });
    for (const other of members.values()) {
      if (other !== conn) send(other.ws, { t: 'peer-joined', peer: info(conn) });
    }
  }

  function onSignal(conn, m) {
    if (!conn.room) return;
    const target = rooms.get(conn.room)?.get(m.to);
    if (!target || target === conn || typeof m.data !== 'object' || m.data === null) {
      return send(conn.ws, { t: 'nopeer', sid: String(m.to).slice(0, 16) });
    }
    send(target.ws, { t: 'signal', from: conn.sid, data: m.data });
  }

  function leaveRoom(conn) {
    if (!conn.room) return;
    const members = rooms.get(conn.room);
    if (members?.get(conn.sid) === conn) {
      members.delete(conn.sid);
      for (const other of members.values()) send(other.ws, { t: 'peer-left', sid: conn.sid });
      if (members.size === 0) rooms.delete(conn.room);
    }
    conn.room = null;
  }

  async function onMessage(conn, m) {
    switch (m.t) {
      case 'join':
        return onJoin(conn, m);
      case 'signal':
        return onSignal(conn, m);
      case 'ping': // keepalive do cliente (mantém serviços gratuitos acordados)
        return send(conn.ws, { t: 'pong' });
      case 'leave':
        return conn.ws.close(1000, 'bye');
      default:
        return undefined;
    }
  }

  wss.on('connection', (ws, req, ip) => {
    connCount += 1;
    ipCount.set(ip, (ipCount.get(ip) ?? 0) + 1);
    ws.isAlive = true;
    const conn = {
      ws,
      ip,
      nonce: randomBytes(16).toString('hex'),
      room: null,
      sid: null,
      fp: null,
      name: '',
      joining: false,
      tokens: RATE_BURST,
      last: Date.now(),
      queue: Promise.resolve(),
    };
    const joinTimer = setTimeout(() => {
      if (!conn.room) ws.close(4001, 'join_timeout');
    }, JOIN_TIMEOUT_MS);

    send(ws, { t: 'hello', v: 2, nonce: conn.nonce, maxPeers: cfg.maxPeers });

    ws.on('pong', () => {
      ws.isAlive = true;
    });
    ws.on('message', (data, isBinary) => {
      if (isBinary) return ws.close(1003, 'binary_not_supported');
      if (!takeToken(conn)) return ws.close(1008, 'rate_limit');
      let msg;
      try {
        msg = JSON.parse(data.toString('utf8'));
      } catch {
        return ws.close(1007, 'bad_json');
      }
      if (!msg || typeof msg !== 'object' || typeof msg.t !== 'string') return ws.close(1007, 'bad_message');
      // Serializa o tratamento por conexão: preserva a ordem e evita corridas no join.
      conn.queue = conn.queue.then(() => onMessage(conn, msg)).catch(() => {
        try {
          ws.close(1011, 'internal');
        } catch {
          /* já fechado */
        }
      });
      return undefined;
    });
    ws.on('close', () => {
      clearTimeout(joinTimer);
      connCount -= 1;
      const left = (ipCount.get(ip) ?? 1) - 1;
      if (left <= 0) ipCount.delete(ip);
      else ipCount.set(ip, left);
      leaveRoom(conn);
    });
    ws.on('error', () => {});
  });

  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.isAlive === false) {
        ws.terminate();
        continue;
      }
      ws.isAlive = false;
      ws.ping();
    }
  }, HEARTBEAT_MS);
  heartbeat.unref();

  return {
    server,
    rooms,
    cfg,
    listen(port = cfg.port, host = cfg.host) {
      return new Promise((resolve) => server.listen(port, host, () => resolve(server.address())));
    },
    close() {
      return new Promise((resolve) => {
        clearInterval(heartbeat);
        for (const ws of wss.clients) ws.terminate();
        wss.close();
        server.close(() => resolve());
        server.closeAllConnections?.();
      });
    },
  };
}

// Execução direta: `node server/server.js`
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const app = createApp();
  app.listen().then((addr) => {
    console.log(`KSLink ouvindo em http://${addr.address}:${addr.port}  (salas de até ${app.cfg.maxPeers} pessoas)`);
  });
  const stop = () => {
    console.log('Encerrando…');
    app.close().then(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
