import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { WebSocket } from 'ws';
import { createApp, loadConfig } from '../server/server.js';
import { generateIdentity, signText, hex } from '../public/crypto.js';

// ───────── utilitários ─────────
async function start(overrides = {}, env = {}) {
  const cfg = loadConfig({ ICE_SERVERS: '[{"urls":"stun:exemplo.org:3478"}]', ...env }, { port: 0, host: '127.0.0.1', ...overrides });
  const app = createApp(cfg);
  const addr = await app.listen();
  return { app, port: addr.port };
}

function client(port, headers) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers });
  const queue = [];
  const waiters = [];
  ws.on('message', (d) => {
    const m = JSON.parse(d.toString());
    const i = waiters.findIndex((w) => w.pred(m));
    if (i >= 0) waiters.splice(i, 1)[0].resolve(m);
    else queue.push(m);
  });
  const closed = new Promise((resolve) => ws.on('close', (code, reason) => resolve({ code, reason: reason.toString() })));
  return {
    ws,
    closed,
    send: (o) => ws.send(JSON.stringify(o)),
    next(t, ms = 2000) {
      const pred = typeof t === 'function' ? t : (m) => m.t === t;
      const i = queue.findIndex(pred);
      if (i >= 0) return Promise.resolve(queue.splice(i, 1)[0]);
      return new Promise((resolve, reject) => {
        const w = { pred, resolve };
        waiters.push(w);
        setTimeout(() => {
          const k = waiters.indexOf(w);
          if (k >= 0) {
            waiters.splice(k, 1);
            reject(new Error(`timeout esperando ${typeof t === 'string' ? t : 'mensagem'}`));
          }
        }, ms);
      });
    },
  };
}

const sidOf = () => hex(globalThis.crypto.getRandomValues(new Uint8Array(8)));

async function join(c, id, room, { sid = sidOf(), name = 'Teste', signer = id } = {}) {
  const hello = await c.next('hello');
  const sig = await signText(signer.priv, `KSLINK-JOIN|v2|${hello.nonce}|${room}|${sid}`);
  c.send({ t: 'join', room, sid, pub: hex(id.pubRaw), name, sig });
  return { sid, hello };
}

function rawGet(port, path) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: 'GET' }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

const upgradeStatus = (port, headers) =>
  new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers });
    ws.on('unexpected-response', (_req, res) => resolve(res.statusCode));
    ws.on('open', () => {
      ws.close();
      resolve(101);
    });
    ws.on('error', () => {});
  });

// ───────── HTTP ─────────
describe('HTTP', () => {
  let ctx;
  before(async () => { ctx = await start(); });
  after(() => ctx.app.close());

  test('/healthz responde ok', async () => {
    const r = await rawGet(ctx.port, '/healthz');
    assert.equal(r.status, 200);
    assert.equal(r.body, 'ok');
  });

  test('cabeçalhos de segurança e CSP restritiva', async () => {
    const r = await rawGet(ctx.port, '/healthz');
    assert.match(r.headers['content-security-policy'], /default-src 'self'/);
    assert.match(r.headers['content-security-policy'], /script-src 'self'(;|$)/);
    assert.doesNotMatch(r.headers['content-security-policy'], /unsafe-inline|unsafe-eval/);
    assert.equal(r.headers['x-content-type-options'], 'nosniff');
    assert.equal(r.headers['referrer-policy'], 'no-referrer');
  });

  test('/ice devolve a configuração e bloqueia origem estranha', async () => {
    const r = await rawGet(ctx.port, '/ice');
    assert.equal(r.status, 200);
    assert.deepEqual(JSON.parse(r.body).iceServers, [{ urls: 'stun:exemplo.org:3478' }]);
    const foreign = await new Promise((resolve) => {
      http.get({ host: '127.0.0.1', port: ctx.port, path: '/ice', headers: { Origin: 'https://evil.example' } }, (res) => {
        res.resume();
        resolve(res.statusCode);
      });
    });
    assert.equal(foreign, 403);
  });

  test('serve estáticos e bloqueia path traversal', async () => {
    const js = await rawGet(ctx.port, '/crypto.js');
    assert.equal(js.status, 200);
    assert.match(js.headers['content-type'], /javascript/);
    for (const p of ['/%2e%2e/server/server.js', '/..%2fserver%2fserver.js', '/%2e%2e%2f%2e%2e%2fetc%2fpasswd', '/fonts/', '/%00', '/package.json']) {
      const r = await rawGet(ctx.port, p);
      assert.notEqual(r.status, 200, `${p} não pode ser servido`);
      assert.ok(!r.body.includes('createApp'), `${p} vazou código do servidor`);
    }
  });

  test('métodos diferentes de GET/HEAD recebem 405', async () => {
    const status = await new Promise((resolve) => {
      const req = http.request({ host: '127.0.0.1', port: ctx.port, path: '/', method: 'POST' }, (res) => {
        res.resume();
        resolve(res.statusCode);
      });
      req.end();
    });
    assert.equal(status, 405);
  });
});

// ───────── Sinalização ─────────
describe('sinalização', () => {
  let ctx;
  const open = [];
  const mk = (headers) => { const c = client(ctx.port, headers); open.push(c); return c; };
  before(async () => { ctx = await start({ maxPeers: 3 }); });
  after(async () => { open.forEach((c) => c.ws.terminate()); await ctx.app.close(); });

  test('join, lista de participantes, peer-joined, relay de sinal e peer-left', async () => {
    const idA = await generateIdentity();
    const idB = await generateIdentity();
    const room = 'sala-principal-01';
    const a = mk();
    const ja = await join(a, idA, room, { name: 'Ana' });
    const joinedA = await a.next('joined');
    assert.deepEqual(joinedA.peers, []);
    assert.equal(joinedA.fp, createHash('sha256').update(idA.pubRaw).digest('hex'));

    const b = mk();
    const jb = await join(b, idB, room, { name: 'Beto' });
    const joinedB = await b.next('joined');
    assert.equal(joinedB.peers.length, 1);
    assert.equal(joinedB.peers[0].sid, ja.sid);
    assert.equal(joinedB.peers[0].name, 'Ana');
    assert.equal(joinedB.peers[0].fp, idA.fp);

    const pj = await a.next('peer-joined');
    assert.equal(pj.peer.sid, jb.sid);
    assert.equal(pj.peer.fp, idB.fp);

    b.send({ t: 'signal', to: ja.sid, data: { sdp: { type: 'offer', sdp: 'x' } } });
    const sig = await a.next('signal');
    assert.equal(sig.from, jb.sid);
    assert.deepEqual(sig.data, { sdp: { type: 'offer', sdp: 'x' } });

    b.send({ t: 'signal', to: 'ffffffffffffffff', data: {} });
    assert.equal((await b.next('nopeer')).sid, 'ffffffffffffffff');

    b.ws.close();
    assert.equal((await a.next('peer-left')).sid, jb.sid);
  });

  test('salas são isoladas: sinal não atravessa para outra sala', async () => {
    const [x, y] = [await generateIdentity(), await generateIdentity()];
    const a = mk(); const b = mk();
    const ja = await join(a, x, 'sala-isolada-aa'); await a.next('joined');
    await join(b, y, 'sala-isolada-bb'); await b.next('joined');
    b.send({ t: 'signal', to: ja.sid, data: { cand: 1 } });
    await b.next('nopeer');
  });

  test('assinatura inválida (outra chave) é rejeitada e a conexão fecha', async () => {
    const [real, impostor] = [await generateIdentity(), await generateIdentity()];
    const c = mk();
    await join(c, real, 'sala-assinatura-1', { signer: impostor });
    assert.equal((await c.next('error')).code, 'bad_signature');
    assert.equal((await c.closed).code, 4000);
  });

  test('assinatura reaproveitada em outra conexão (replay) é rejeitada', async () => {
    const id = await generateIdentity();
    const room = 'sala-replay-0001';
    const sid = sidOf();
    const c1 = mk();
    const h1 = await c1.next('hello');
    const sig = await signText(id.priv, `KSLINK-JOIN|v2|${h1.nonce}|${room}|${sid}`);
    const c2 = mk();
    await c2.next('hello'); // nonce diferente
    c2.send({ t: 'join', room, sid, pub: hex(id.pubRaw), name: 'x', sig });
    assert.equal((await c2.next('error')).code, 'bad_signature');
  });

  test('sala cheia e sid duplicado são recusados', async () => {
    const room = 'sala-cheia-00001';
    const ids = await Promise.all([1, 2, 3, 4].map(() => generateIdentity()));
    const members = [];
    for (let i = 0; i < 3; i += 1) {
      const c = mk();
      const j = await join(c, ids[i], room);
      await c.next('joined');
      members.push({ c, sid: j.sid });
    }
    const extra = mk();
    await join(extra, ids[3], room);
    assert.equal((await extra.next('error')).code, 'room_full');

    // Libera uma vaga e tenta entrar reutilizando o sid de quem continua na sala.
    members[2].c.ws.close();
    await members[0].c.next('peer-left');
    const dup = mk();
    await join(dup, ids[3], room, { sid: members[0].sid });
    assert.equal((await dup.next('error')).code, 'sid_in_use');
  });

  test('reconexão: a mesma identidade assume o sid de um socket antigo ainda aberto', async () => {
    const room = 'sala-takeover-01';
    const idA = await generateIdentity();
    const idB = await generateIdentity();
    const a = mk();
    const ja = await join(a, idA, room);
    await a.next('joined');
    const b = mk();
    await join(b, idB, room);
    await b.next('joined');
    await a.next('peer-joined');
    // A "cai" sem o servidor perceber: novo socket, mesma identidade e mesmo sid
    const a2 = mk();
    await join(a2, idA, room, { sid: ja.sid });
    const joined = await a2.next('joined');
    assert.equal(joined.sid, ja.sid);
    assert.equal(joined.peers.length, 1);
    // Outra identidade com o mesmo sid continua recusada
    const evil = mk();
    await join(evil, idB, room, { sid: ja.sid });
    assert.equal((await evil.next('error')).code, 'sid_in_use');
  });

  test('entradas inválidas: room, sid e pub malformados', async () => {
    const id = await generateIdentity();
    for (const bad of [{ room: 'curto' }, { room: 'sala com espaço!!' }, { sid: 'zz' }]) {
      const c = mk();
      const hello = await c.next('hello');
      const params = { room: 'sala-valida-0001', sid: sidOf(), ...bad };
      const sig = await signText(id.priv, `KSLINK-JOIN|v2|${hello.nonce}|${params.room}|${params.sid}`);
      c.send({ t: 'join', ...params, pub: hex(id.pubRaw), name: 'x', sig });
      assert.equal((await c.next('error')).code, 'bad_request');
    }
    const c = mk();
    await c.next('hello');
    c.send({ t: 'join', room: 'sala-valida-0001', sid: sidOf(), pub: 'ab', name: 'x', sig: 'cd' });
    assert.equal((await c.next('error')).code, 'bad_request');
  });

  test('nome é saneado e limitado a 32 caracteres', async () => {
    const [x, y] = [await generateIdentity(), await generateIdentity()];
    const room = 'sala-nome-000001';
    const a = mk(); await join(a, x, room, { name: `  \u0007${'N'.repeat(80)}  ` }); await a.next('joined');
    const b = mk(); await join(b, y, room); const jb = await b.next('joined');
    assert.equal(jb.peers[0].name, 'N'.repeat(32));
  });

  test('sinal antes do join é ignorado; ping responde pong', async () => {
    const id = await generateIdentity();
    const c = mk();
    await c.next('hello');
    c.send({ t: 'signal', to: 'aaaaaaaaaaaaaaaa', data: {} });
    c.send({ t: 'ping' });
    await c.next('pong');
    assert.equal(c.ws.readyState, WebSocket.OPEN);
    void id;
  });

  test('mensagem binária, JSON inválido e excesso de mensagens derrubam a conexão', async () => {
    const b1 = mk(); await b1.next('hello'); b1.ws.send(Buffer.from([1, 2, 3]));
    assert.equal((await b1.closed).code, 1003);
    const b2 = mk(); await b2.next('hello'); b2.ws.send('{não é json');
    assert.equal((await b2.closed).code, 1007);
    const b3 = mk(); await b3.next('hello');
    for (let i = 0; i < 600; i += 1) b3.send({ t: 'ping' });
    assert.equal((await b3.closed).code, 1008);
  });

  test('sem join no prazo a conexão é encerrada', { timeout: 15000 }, async () => {
    const c = mk();
    await c.next('hello');
    assert.equal((await c.closed).code, 4001);
  });
});

// ───────── Origem e limites ─────────
describe('origem e limites', () => {
  test('WebSocket de origem estranha é recusado; mesma origem e lista permitida passam', async () => {
    const { app, port } = await start();
    assert.equal(await upgradeStatus(port, { Origin: 'https://evil.example' }), 403);
    assert.equal(await upgradeStatus(port, { Origin: `http://127.0.0.1:${port}` }), 101);
    assert.equal(await upgradeStatus(port, undefined), 101);
    await app.close();

    const allowed = await start({ allowedOrigins: ['https://meu-site.example'] });
    assert.equal(await upgradeStatus(allowed.port, { Origin: 'https://meu-site.example' }), 101);
    assert.equal(await upgradeStatus(allowed.port, { Origin: 'https://evil.example' }), 403);
    await allowed.app.close();
  });

  test('limite de conexões por IP responde 429', async () => {
    const { app, port } = await start({ maxConnPerIp: 2 });
    const a = client(port); const b = client(port);
    await a.next('hello'); await b.next('hello');
    assert.equal(await upgradeStatus(port), 429);
    a.ws.close();
    await a.closed;
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(await upgradeStatus(port), 101);
    b.ws.terminate();
    await app.close();
  });

  test('sala vazia é removida da memória', async () => {
    const { app, port } = await start();
    const id = await generateIdentity();
    const c = client(port);
    await join(c, id, 'sala-efemera-001'); await c.next('joined');
    assert.equal(app.rooms.size, 1);
    c.ws.close(); await c.closed;
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(app.rooms.size, 0);
    await app.close();
  });
});
