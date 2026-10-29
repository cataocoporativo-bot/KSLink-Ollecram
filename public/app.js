// KSLink 2.0 — cliente.
//
// Arquitetura:
//   • O servidor só faz a SINALIZAÇÃO (troca de SDP/ICE) e nunca vê o conteúdo.
//   • Cada par de participantes abre um RTCDataChannel direto (malha completa).
//   • Cada canal faz um handshake assinado pela identidade persistente de cada um,
//     com vínculo aos fingerprints DTLS, e deriva uma chave AES-GCM própria.
//   • Mensagens e arquivos são cifrados separadamente para cada destinatário.
//
// Todo texto vindo de outros participantes é inserido com textContent (nunca innerHTML).

import {
  hex, utf8, fromUtf8, randomBytes, unhex, shortFp, fingerprint,
  signText, verifyText, hsTranscript, dtlsFingerprint,
  generateEphemeral, deriveSessionKey, sealBytes, openBytes,
  exportBackup, importBackup,
} from './crypto.js';
import {
  loadOrCreateIdentity, saveIdentity, getName, setName,
  getVerified, toggleVerified, getServer, setServer,
} from './store.js';

// ───────────────────────── constantes ─────────────────────────
const CHUNK = 32 * 1024;
const MAX_FILE = 100 * 1024 * 1024;
const HIGH_WATER = 1024 * 1024;
const LOW_WATER = 256 * 1024;
const K_JSON = 1;
const K_FILE = 2;
const CONN_TIMEOUT_MS = 20_000;
const KEEPALIVE_MS = 4 * 60 * 1000;
const MAX_RETRIES = 3;
const MAX_INBOUND_FILES = 4;
const FALLBACK_ICE = [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun1.l.google.com:19302' }];

const ST = {
  waiting: ['aguardando', 'muted'],
  connecting: ['conectando…', 'warn'],
  handshake: ['verificando…', 'warn'],
  secure: ['seguro', 'ok'],
  failed: ['sem conexão', 'err'],
};

const S = {
  identity: null,
  sidRetries: 0,
  sid: hex(randomBytes(8)), // identifica esta aba/sessão (a identidade é compartilhada entre abas)
  name: '',
  room: null,
  wantRoom: false,
  ws: null,
  retry: 0,
  retryTimer: null,
  maxPeers: 8,
  iceServers: FALLBACK_ICE,
  iceLoaded: false,
  peers: new Map(), // sid -> peer
};

// ───────────────────────── utilidades ─────────────────────────
const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

// Remove controles, espaços invisíveis e caracteres bidi (evitam falsificar nomes).
const BAD_CHARS = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g;
const sanitizeName = (s, max = 24) => String(s ?? '').replace(BAD_CHARS, '').replace(/\s+/g, ' ').trim().slice(0, max);

function sanitizeFileName(s) {
  const n = String(s ?? '').replace(BAD_CHARS, '').replace(/[\\/:*?"<>|]/g, '_').replace(/^\.+/, '').trim().slice(0, 120);
  return n || 'arquivo';
}

const validSid = (s) => typeof s === 'string' && /^[0-9a-f]{16}$/.test(s);

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

const ICONS = {
  pdf: '📄', doc: '📝', docx: '📝', xls: '📊', xlsx: '📊', ppt: '📊', pptx: '📊',
  zip: '🗜️', rar: '🗜️', '7z': '🗜️', png: '🖼️', jpg: '🖼️', jpeg: '🖼️', gif: '🖼️', webp: '🖼️', svg: '🖼️',
  mp4: '🎬', mov: '🎬', avi: '🎬', mkv: '🎬', mp3: '🎵', wav: '🎵', ogg: '🎵', flac: '🎵',
  txt: '📃', md: '📃', json: '📃', csv: '📃',
};
const fileIcon = (name) => ICONS[name.split('.').pop().toLowerCase()] ?? '📁';

const timeNow = () => new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });

let toastTimer;
function toast(msg, type = 'ok') {
  const t = $('toast');
  t.textContent = msg;
  t.className = `toast ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 3800);
}

async function copyText(text, okMsg) {
  try {
    await navigator.clipboard.writeText(text);
    toast(okMsg);
  } catch {
    const ta = el('textarea');
    ta.value = text;
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand?.('copy');
    ta.remove();
    toast(ok ? okMsg : 'Não foi possível copiar. Selecione e copie manualmente.', ok ? 'ok' : 'err');
  }
}

function autoH(t) {
  t.style.height = 'auto';
  t.style.height = `${Math.min(t.scrollHeight, 120)}px`;
}

const isMobile = () => window.matchMedia('(max-width: 700px)').matches;
const openDrawer = () => $('sidebar').classList.add('open');
const closeDrawer = () => $('sidebar').classList.remove('open');

// ───────────────────────── mensagens na tela ─────────────────────────
const emptyEl = $('emptyState');
const msgsEl = $('msgs');

function pushMsg(node) {
  emptyEl.classList.add('hidden');
  msgsEl.append(node);
  msgsEl.scrollTop = msgsEl.scrollHeight;
}

function clearChat() {
  if (typeof setReply === 'function') setReply(null);
  msgsEl.replaceChildren(emptyEl);
  emptyEl.classList.remove('hidden');
}

function sysMsg(text, kind = '') {
  const w = el('div', `msg system ${kind}`.trim());
  w.append(el('div', 'bubble', text));
  pushMsg(w);
}

const newMid = () => hex(randomBytes(6));
let replyTo = null; // { id, name, text }

function setReply(r) {
  replyTo = r;
  $('replyBar').classList.toggle('hidden', !r);
  if (r) {
    $('replyWho').textContent = r.name;
    $('replyBody').textContent = r.text;
    $('msgInput').focus();
  }
}

const DELETED_TXT = 'Mensagem apagada';

/** Troca o conteúdo da mensagem por um aviso e limpa as citações dela. */
function tombstone(w) {
  const id = w.dataset.mid;
  w.classList.add('deleted');
  w.replaceChildren();
  if (w.classList.contains('received') && w.dataset.who) w.append(el('div', 'who', w.dataset.who));
  w.append(el('div', 'bubble', `🚫 ${DELETED_TXT}`));
  w.append(el('div', 'meta', timeNow()));
  for (const q of msgsEl.querySelectorAll('.quote')) {
    if (q.dataset.qid === id) q.querySelector('.q-txt').textContent = DELETED_TXT;
  }
  if (replyTo?.id === id) setReply(null);
}

function deleteButton(meta, w) {
  const b = el('button', 'reply-btn del-btn', '🗑');
  b.type = 'button';
  b.title = 'Apagar para todos';
  b.setAttribute('aria-label', 'Apagar para todos');
  b.addEventListener('click', async () => {
    if (!window.confirm('Apagar esta mensagem para todos os participantes?')) return;
    const id = w.dataset.mid;
    const targets = securePeers();
    await Promise.allSettled(targets.map((p) => sendJson(p, { k: 'del', id })));
    tombstone(w);
  });
  meta.append(b);
}

function jumpTo(id) {
  const t = [...msgsEl.querySelectorAll('.msg[data-mid]')].find((n) => n.dataset.mid === id);
  if (!t) return toast('A mensagem original não está mais na tela.', 'err');
  t.scrollIntoView({ block: 'center', behavior: 'smooth' });
  t.classList.remove('flash');
  void t.offsetWidth;
  t.classList.add('flash');
  return undefined;
}

function replyButton(meta, w, name, text) {
  const b = el('button', 'reply-btn', '↩');
  b.type = 'button';
  b.title = 'Responder';
  b.setAttribute('aria-label', 'Responder');
  b.addEventListener('click', () => setReply({ id: w.dataset.mid, name, text: text.slice(0, 140) }));
  meta.append(b);
}

function addMsg({ dir, name, text, to, total, id, re, from }) {
  const w = el('div', `msg ${dir}`);
  if (id) w.dataset.mid = id;
  if (from) w.dataset.from = from;
  if (dir === 'received') w.dataset.who = name;
  if (dir === 'received') w.append(el('div', 'who', name));
  if (re) {
    const q = el('div', 'quote');
    q.dataset.qid = re.id;
    q.append(el('div', 'q-who', re.name), el('div', 'q-txt', re.text));
    q.addEventListener('click', () => jumpTo(re.id));
    w.append(q);
  }
  w.append(el('div', 'bubble', text));
  const meta = el('div', 'meta');
  meta.append(el('span', '', timeNow()));
  if (dir === 'sent') {
    const c = el('span', 'ci', `🔒 ${to}/${total}`);
    c.title = `Entregue a ${to} de ${total} participantes`;
    meta.append(c);
  } else {
    meta.append(el('span', 'ci', '🔒'));
  }
  if (id) replyButton(meta, w, dir === 'sent' ? 'Você' : name, text);
  if (id && dir === 'sent') deleteButton(meta, w);
  w.append(meta);
  pushMsg(w);
}

// ───────────────────────── som de notificação ─────────────────────────
let audioCtx = null;
let soundOn = true;
try { soundOn = localStorage.getItem('kslink.sound') !== 'off'; } catch { /* sem armazenamento */ }

function renderSoundBtn() {
  const b = $('soundBtn');
  b.textContent = soundOn ? '🔔' : '🔕';
  b.classList.toggle('off', !soundOn);
  b.title = soundOn ? 'Som ligado (clique para silenciar)' : 'Som desligado (clique para ligar)';
}

function unlockAudio() {
  try {
    audioCtx ||= new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === 'suspended') audioCtx.resume();
  } catch { /* sem áudio */ }
}

function playPing() {
  if (!soundOn) return;
  try {
    unlockAudio();
    if (!audioCtx || audioCtx.state !== 'running') return;
    const t0 = audioCtx.currentTime;
    [[880, 0], [1320, 0.11]].forEach(([f, d]) => {
      const o = audioCtx.createOscillator();
      const g = audioCtx.createGain();
      o.type = 'sine';
      o.frequency.value = f;
      g.gain.setValueAtTime(0.0001, t0 + d);
      g.gain.exponentialRampToValueAtTime(0.18, t0 + d + 0.015);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + d + 0.22);
      o.connect(g).connect(audioCtx.destination);
      o.start(t0 + d);
      o.stop(t0 + d + 0.25);
    });
  } catch { /* sem áudio */ }
}

function fileBubble({ dir, name, size, from, label }) {
  const w = el('div', `msg ${dir}`);
  if (dir === 'received') w.append(el('div', 'who', from));
  const b = el('div', 'file-bubble');
  const info = el('div', 'file-info');
  info.append(el('div', 'file-icon', fileIcon(name)));
  const t = el('div');
  t.append(el('div', 'file-name', name), el('div', 'file-size', formatBytes(size)));
  info.append(t);
  const bar = el('div', 'progress-bar');
  const wrap = el('div', 'progress-wrap');
  wrap.append(bar);
  const lab = el('div', 'progress-label', label);
  b.append(info, wrap, lab);
  w.append(b);
  const meta = el('div', 'meta');
  meta.append(el('span', '', timeNow()), el('span', 'ci', '🔒'));
  w.append(meta);
  pushMsg(w);
  return {
    progress(f, text) {
      bar.style.width = `${Math.round(f * 100)}%`;
      if (text) lab.textContent = text;
    },
    done(text) {
      bar.style.width = '100%';
      lab.textContent = text;
    },
    fail(text) {
      lab.textContent = text;
      w.classList.add('failed');
    },
    download(url, blob) {
      if (window.ReactNativeWebView) {
        // App móvel (WebView): downloads por blob: não funcionam; entrega ao app nativo.
        const btn = el('button', 'dl-btn', '⬇️ Salvar');
        btn.type = 'button';
        btn.addEventListener('click', () => saveViaNative(blob, name));
        b.append(btn);
        return;
      }
      const a = el('a', 'dl-btn', '⬇️ Baixar');
      a.href = url;
      a.download = name;
      b.append(a);
    },
  };
}

// ───────────────────────── renderização ─────────────────────────
const securePeers = () => [...S.peers.values()].filter((p) => p.state === 'secure' && p.key && p.dc?.readyState === 'open');

function setNet(state) {
  const map = {
    off: ['Offline', ''],
    connecting: ['Conectando…', 'connecting'],
    reconnecting: ['Reconectando…', 'connecting'],
    on: ['Online', 'on'],
  };
  const [txt, cls] = map[state];
  $('netTxt').textContent = txt;
  $('netDot').className = `dot ${cls}`;
}

function peerRow(p) {
  const self = !p;
  const verified = getVerified();
  const li = el('li', `peer${self ? ' self' : ''}`);
  const name = self ? S.name : p.name;
  li.append(el('div', 'p-av', (name[0] ?? '?').toUpperCase()));

  const main = el('div', 'p-main');
  main.append(el('div', 'p-name', self ? `${name} (você)` : name));
  const sub = el('div', 'p-sub');
  if (self) {
    sub.append(el('span', 'st ok', '● online'));
  } else {
    const [txt, cls] = ST[p.state];
    sub.append(el('span', `st ${cls}`, `● ${txt}`));
  }
  const fp = self ? S.identity.fp : p.idFp;
  if (fp) sub.append(el('span', '', shortFp(fp, 3)));
  if (!self && p.idFp && p.idFp === S.identity.fp) sub.append(el('span', '', 'mesma identidade (outra aba)'));
  main.append(sub);
  li.append(main);

  if (!self && p.idFp) {
    const isV = verified.has(p.idFp);
    const b = el('button', `mini-btn${isV ? ' on' : ''}`, isV ? '✔' : '○');
    b.type = 'button';
    b.title = isV
      ? 'Identidade verificada (toque para desmarcar)'
      : 'Compare a impressão digital com a pessoa por outro canal e marque como verificada';
    b.addEventListener('click', () => {
      toggleVerified(p.idFp);
      renderPeers();
    });
    li.append(b);
  }
  if (!self && (p.state === 'failed' || p.state === 'waiting') && S.ws?.readyState === 1) {
    const r = el('button', 'mini-btn', '↻');
    r.type = 'button';
    r.title = 'Tentar reconectar';
    r.addEventListener('click', () => {
      p.retries = 0;
      requestConnection(p);
    });
    li.append(r);
  }
  return li;
}

function renderPeers() {
  const ul = $('peerList');
  ul.replaceChildren();
  $('peerCount').textContent = S.room ? `(${S.peers.size + 1}/${S.maxPeers})` : '';
  if (!S.room) return;
  ul.append(peerRow(null));
  for (const p of S.peers.values()) ul.append(peerRow(p));
}

function renderRoom() {
  $('roomIdle').classList.toggle('hidden', !!S.room);
  $('roomActive').classList.toggle('hidden', !S.room);
  if (S.room) $('roomLink').value = roomLink(S.room);
}

function renderChatHeader() {
  const n = securePeers().length;
  $('chatTitle').textContent = S.room ? `Sala ${S.room}` : 'Nenhuma sala';
  $('chatSub').textContent = S.room
    ? `${n} conectado${n === 1 ? '' : 's'} com segurança · ${S.peers.size + 1} na sala`
    : 'Crie ou entre em uma sala';
  const badge = $('e2eeBadge');
  badge.classList.toggle('active', n > 0);
  badge.querySelector('.badge-txt').textContent = n > 0 ? 'E2EE ativo' : 'E2EE inativo';
}

function renderComposer() {
  const on = securePeers().length > 0;
  $('msgInput').disabled = !on;
  $('sendBtn').disabled = !on;
  $('attachBtn').disabled = !on;
  $('msgInput').placeholder = on ? 'Mensagem cifrada…' : 'Aguardando alguém conectar…';
}

function renderAll() {
  renderRoom();
  renderPeers();
  renderChatHeader();
  renderComposer();
}

// ───────────────────────── sala ─────────────────────────
const ROOM_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

function newRoomCode() {
  let s = '';
  let n = 0;
  while (n < 12) {
    const b = randomBytes(1)[0];
    if (b >= 248) continue; // descarta para não enviesar (248 = 31 × 8)
    s += ROOM_ALPHABET[b % 31];
    n += 1;
    if (n === 4 || n === 8) s += '-';
  }
  return s;
}

function parseRoom(input) {
  let s = String(input ?? '').trim();
  const i = s.indexOf('#r=');
  if (i >= 0) s = s.slice(i + 3);
  s = s.toLowerCase();
  return /^[a-z0-9_-]{6,64}$/.test(s) ? s : null;
}

const roomLink = (room) => `${location.origin}${location.pathname}#r=${room}`;

function commitName() {
  const n = sanitizeName($('nameInput').value);
  $('nameInput').value = n;
  S.name = n || `Anônimo-${S.identity.fp.slice(0, 4)}`;
  setName(n);
}

async function enterRoom(raw) {
  const room = parseRoom(raw);
  if (!room) {
    toast('Código ou link de sala inválido.', 'err');
    return;
  }
  commitName();
  if (S.room) leaveRoom();
  S.room = room;
  S.wantRoom = true;
  S.retry = 0;
  history.replaceState(null, '', `#r=${room}`);
  renderAll();
  sysMsg(`Entrando na sala ${room}…`);
  if (!S.iceLoaded) await loadIce();
  if (S.room === room && S.wantRoom) connectWs();
}

function leaveRoom() {
  S.wantRoom = false;
  clearTimeout(S.retryTimer);
  for (const p of S.peers.values()) {
    clearTimeout(p.retryTimer);
    closeConn(p);
  }
  S.peers.clear();
  const ws = S.ws;
  S.ws = null;
  if (ws) {
    try {
      if (ws.readyState === 1) ws.send('{"t":"leave"}');
      ws.close();
    } catch {
      /* já fechado */
    }
  }
  S.room = null;
  S.retry = 0;
  history.replaceState(null, '', location.pathname + location.search);
  clearChat();
  setNet('off');
  renderAll();
}

// ───────────────────────── servidor de sinalização ─────────────────────────
function serverUrl() {
  const custom = getServer().trim();
  if (!custom) {
    if (location.protocol !== 'http:' && location.protocol !== 'https:') {
      throw new Error('Defina o servidor em "Identidade e servidor".');
    }
    return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;
  }
  let u = custom;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) u = `wss://${u}`;
  u = u.replace(/^http:/i, 'ws:').replace(/^https:/i, 'wss:');
  const url = new URL(u);
  if (url.protocol !== 'ws:' && url.protocol !== 'wss:') throw new Error('Endereço de servidor inválido.');
  if (url.pathname === '/' || url.pathname === '') url.pathname = '/ws';
  return url.toString();
}

function httpBase() {
  const u = new URL(serverUrl());
  u.protocol = u.protocol === 'wss:' ? 'https:' : 'http:';
  return u.origin;
}

async function loadIce() {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 4000);
    const r = await fetch(`${httpBase()}/ice`, { signal: ctrl.signal, cache: 'no-store' });
    clearTimeout(t);
    if (r.ok) {
      const j = await r.json();
      if (Array.isArray(j.iceServers)) S.iceServers = j.iceServers;
    }
  } catch {
    /* usa o padrão */
  }
  S.iceLoaded = true;
}

function connectWs() {
  clearTimeout(S.retryTimer);
  if (!S.wantRoom) return;
  let ws;
  try {
    ws = new WebSocket(serverUrl());
  } catch (e) {
    toast(e.message || 'Não foi possível abrir o servidor.', 'err');
    leaveRoom();
    return;
  }
  S.ws = ws;
  setNet(S.retry > 0 ? 'reconnecting' : 'connecting');
  ws.onmessage = (ev) => {
    if (S.ws !== ws) return;
    let m;
    try {
      m = JSON.parse(ev.data);
    } catch {
      return;
    }
    onServerMsg(ws, m).catch(() => {});
  };
  ws.onclose = () => {
    if (S.ws !== ws) return;
    S.ws = null;
    if (!S.wantRoom) return;
    setNet('reconnecting');
    renderPeers();
    const delay = Math.min(15_000, 1000 * 2 ** S.retry);
    S.retry += 1;
    S.retryTimer = setTimeout(connectWs, delay);
  };
  ws.onerror = () => {};
}

const ERRORS = {
  room_full: 'Sala cheia.',
  server_busy: 'Servidor ocupado. Tente em instantes.',
  bad_signature: 'Falha na autenticação com o servidor.',
  bad_request: 'Pedido inválido para o servidor.',
  sid_in_use: 'Sessão duplicada. Recarregue a página.',
};

async function onServerMsg(ws, m) {
  switch (m.t) {
    case 'hello': {
      S.maxPeers = Number(m.maxPeers) || S.maxPeers;
      const sig = await signText(S.identity.priv, `KSLINK-JOIN|v2|${m.nonce}|${S.room}|${S.sid}`);
      if (S.ws === ws && ws.readyState === 1) {
        ws.send(JSON.stringify({ t: 'join', room: S.room, sid: S.sid, pub: hex(S.identity.pubRaw), name: S.name, sig }));
      }
      break;
    }
    case 'joined':
      S.retry = 0;
      S.sidRetries = 0;
      setNet('on');
      reconcile(Array.isArray(m.peers) ? m.peers : []);
      break;
    case 'peer-joined':
      if (m.peer && validSid(m.peer.sid) && m.peer.sid !== S.sid) {
        getOrAddPeer(m.peer); // quem entra é quem inicia a conexão; só aguardamos a oferta
        renderAll();
      }
      break;
    case 'peer-left': {
      const p = S.peers.get(m.sid);
      if (p) removePeer(p);
      break;
    }
    case 'signal':
      if (validSid(m.from)) handleSignal(m.from, m.data);
      break;
    case 'error':
      if (m.code === 'sid_in_use' && S.wantRoom && S.sidRetries++ < 3) {
        // Outra sessão (de outra pessoa) usa este id: gera um novo e tenta de novo, sem perder o chat.
        S.sid = hex(randomBytes(8));
        break;
      }
      toast(ERRORS[m.code] || 'Erro no servidor.', 'err');
      leaveRoom();
      break;
    default:
      break;
  }
}

function sigSend(p, payload) {
  if (S.ws?.readyState !== 1) return;
  S.ws.send(JSON.stringify({ t: 'signal', to: p.sid, data: { ...payload, ses: p.ses } }));
}

// ───────────────────────── participantes / malha ─────────────────────────
function newPeer(info) {
  return {
    sid: info.sid,
    name: sanitizeName(info.name) || 'Participante',
    idFp: null,
    state: 'waiting',
    ses: null,
    pc: null,
    dc: null,
    gen: 0,
    pend: [],
    remoteSet: false,
    chain: Promise.resolve(),
    rx: Promise.resolve(),
    key: null,
    eph: null,
    theirEph: null,
    theirEphHex: null,
    dtls: null,
    hsStarted: false,
    hsSent: false,
    hsRecv: false,
    finishing: false,
    everSecure: false,
    connTimer: null,
    discTimer: null,
    retryTimer: null,
    retries: 0,
    inFiles: new Map(),
  };
}

function getOrAddPeer(info) {
  let p = S.peers.get(info.sid);
  if (!p) {
    p = newPeer(info);
    S.peers.set(info.sid, p);
  }
  return p;
}

function reconcile(list) {
  const present = new Set(list.map((x) => x.sid));
  for (const p of [...S.peers.values()]) if (!present.has(p.sid)) removePeer(p);
  for (const info of list) {
    if (!validSid(info.sid) || info.sid === S.sid) continue;
    const p = getOrAddPeer(info);
    if (p.state === 'waiting' || p.state === 'failed') connectTo(p); // somos o "recém-chegado": iniciamos
  }
  renderAll();
}

function removePeer(p) {
  clearTimeout(p.retryTimer);
  closeConn(p);
  abortInbound(p, 'participante saiu');
  S.peers.delete(p.sid);
  if (p.everSecure) sysMsg(`${p.name} saiu`);
  renderAll();
}

/** Encerra pc/dc atuais. Incrementar `gen` invalida todos os callbacks antigos. */
function closeConn(p) {
  clearTimeout(p.connTimer);
  clearTimeout(p.discTimer);
  const { pc, dc } = p;
  p.pc = null;
  p.dc = null;
  p.key = null;
  p.gen += 1;
  try { dc?.close(); } catch { /* ok */ }
  try { pc?.close(); } catch { /* ok */ }
}

function resetConn(p, state) {
  closeConn(p);
  p.state = state;
  p.pend = [];
  p.remoteSet = false;
  p.eph = null;
  p.theirEph = null;
  p.dtls = null;
  p.hsStarted = false;
  p.hsSent = false;
  p.hsRecv = false;
  p.finishing = false;
  return p.gen;
}

function startConnTimeout(p, gen) {
  clearTimeout(p.connTimer);
  p.connTimer = setTimeout(() => {
    if (p.gen === gen && p.state !== 'secure') failPeer(p, gen, 'tempo esgotado ao conectar');
  }, CONN_TIMEOUT_MS);
}

function failPeer(p, gen, why, security = false) {
  if (p.gen !== gen) return;
  const was = p.state;
  closeConn(p);
  p.state = 'failed';
  abortInbound(p, 'conexão interrompida');
  if (security) sysMsg(`⚠️ ${why}`, 'err');
  else if (was === 'secure') sysMsg(`⚠️ Conexão com ${p.name} perdida. Tentando reconectar…`, 'warn');
  renderAll();
  if (!security) scheduleReconnect(p);
}

function inProgress(p) {
  return p.state === 'connecting' || p.state === 'handshake';
}

/** Quem tem o menor sid reinicia; o outro lado pede. Evita as duas pontas ofertarem juntas. */
function requestConnection(p) {
  if (S.ws?.readyState !== 1 || !S.peers.has(p.sid)) return;
  if (S.sid < p.sid) connectTo(p);
  else sigSend(p, { retry: true });
}

function scheduleReconnect(p) {
  clearTimeout(p.retryTimer);
  if (!S.room || !S.peers.has(p.sid) || p.retries >= MAX_RETRIES) return;
  const delay = 1500 * (p.retries + 1) + Math.random() * 500;
  p.retries += 1;
  p.retryTimer = setTimeout(() => {
    if (!S.peers.has(p.sid) || p.state === 'secure' || inProgress(p)) return;
    requestConnection(p);
  }, delay);
}

function makePc(p, gen) {
  const pc = new RTCPeerConnection({ iceServers: S.iceServers });
  p.pc = pc;
  pc.onicecandidate = (e) => {
    if (p.gen === gen && e.candidate) sigSend(p, { cand: e.candidate.toJSON() });
  };
  pc.onconnectionstatechange = () => {
    if (p.gen !== gen) return;
    clearTimeout(p.discTimer);
    if (pc.connectionState === 'failed') {
      failPeer(p, gen, 'conexão falhou');
    } else if (pc.connectionState === 'disconnected') {
      p.discTimer = setTimeout(() => {
        if (p.gen === gen && pc.connectionState === 'disconnected') failPeer(p, gen, 'conexão perdida');
      }, 6000);
    }
  };
  return pc;
}

async function connectTo(p) {
  const gen = resetConn(p, 'connecting');
  p.ses = hex(randomBytes(8));
  renderAll();
  try {
    const pc = makePc(p, gen);
    wireDc(p, pc.createDataChannel('kslink', { ordered: true }), gen);
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    if (p.gen !== gen) return;
    sigSend(p, { sdp: { type: 'offer', sdp: pc.localDescription.sdp } });
    startConnTimeout(p, gen);
  } catch {
    failPeer(p, gen, 'não foi possível iniciar a conexão');
  }
}

function handleSignal(from, data) {
  const p = S.peers.get(from);
  if (!p) return;
  // Serializa por participante: preserva a ordem oferta → resposta → candidatos.
  p.chain = p.chain.then(() => processSignal(p, data)).catch(() => failPeer(p, p.gen, 'erro de sinalização'));
}

const validCand = (c) =>
  c && typeof c.candidate === 'string' && c.candidate.length < 2000 &&
  (c.sdpMid == null || typeof c.sdpMid === 'string') &&
  (c.sdpMLineIndex == null || Number.isInteger(c.sdpMLineIndex));

async function flushCands(p, gen) {
  const list = p.pend;
  p.pend = [];
  for (const c of list) {
    if (p.gen !== gen || !p.pc) return;
    try { await p.pc.addIceCandidate(c); } catch { /* candidato obsoleto */ }
  }
}

async function processSignal(p, data) {
  if (!data || typeof data !== 'object') return;

  if (data.retry === true) {
    if (S.sid < p.sid && !inProgress(p)) connectTo(p);
    return;
  }

  if (data.sdp && typeof data.sdp === 'object') {
    const { type, sdp } = data.sdp;
    if (typeof sdp !== 'string' || sdp.length > 20_000) return;

    if (type === 'offer') {
      if (typeof data.ses !== 'string' || !/^[0-9a-f]{16}$/.test(data.ses)) return;
      // Colisão (as duas pontas ofertaram): a oferta do menor sid prevalece.
      if (p.pc?.signalingState === 'have-local-offer' && S.sid < p.sid) return;
      const gen = resetConn(p, 'connecting');
      p.ses = data.ses;
      const pc = makePc(p, gen);
      pc.ondatachannel = (e) => wireDc(p, e.channel, gen);
      await pc.setRemoteDescription({ type: 'offer', sdp });
      if (p.gen !== gen) return;
      p.remoteSet = true;
      await flushCands(p, gen);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      if (p.gen !== gen) return;
      sigSend(p, { sdp: { type: 'answer', sdp: pc.localDescription.sdp } });
      startConnTimeout(p, gen);
      renderAll();
    } else if (type === 'answer') {
      if (data.ses !== p.ses || !p.pc || p.pc.signalingState !== 'have-local-offer') return;
      const gen = p.gen;
      await p.pc.setRemoteDescription({ type: 'answer', sdp });
      if (p.gen !== gen) return;
      p.remoteSet = true;
      await flushCands(p, gen);
    }
    return;
  }

  if (data.cand) {
    if (data.ses !== p.ses || !p.pc || !validCand(data.cand)) return;
    const c = {
      candidate: data.cand.candidate,
      sdpMid: data.cand.sdpMid ?? null,
      sdpMLineIndex: data.cand.sdpMLineIndex ?? null,
      usernameFragment: typeof data.cand.usernameFragment === 'string' ? data.cand.usernameFragment : undefined,
    };
    if (!p.remoteSet) {
      if (p.pend.length < 100) p.pend.push(c);
    } else {
      try { await p.pc.addIceCandidate(c); } catch { /* candidato obsoleto */ }
    }
  }
}

// ───────────────────────── canal de dados + handshake ─────────────────────────
function wireDc(p, dc, gen) {
  if (p.gen !== gen) {
    try { dc.close(); } catch { /* ok */ }
    return;
  }
  p.dc = dc;
  dc.binaryType = 'arraybuffer';
  dc.bufferedAmountLowThreshold = LOW_WATER;
  dc.onopen = () => {
    if (p.gen === gen) startHandshake(p, gen);
  };
  dc.onclose = () => {
    if (p.gen === gen) failPeer(p, gen, 'canal fechado');
  };
  dc.onmessage = (ev) => {
    if (p.gen !== gen) return;
    // Processa em ordem, esperando operações assíncronas (verificação, derivação de chave).
    p.rx = p.rx.then(() => onDcData(p, gen, ev.data)).catch(() => {});
  };
  if (dc.readyState === 'open') startHandshake(p, gen);
}

async function startHandshake(p, gen) {
  if (p.hsStarted) return;
  p.hsStarted = true;
  p.state = 'handshake';
  try {
    const loc = dtlsFingerprint(p.pc.localDescription.sdp);
    const rem = dtlsFingerprint(p.pc.remoteDescription.sdp);
    p.dtls = { loc, rem };
    p.eph = await generateEphemeral();
    const name = S.name;
    const sig = await signText(
      S.identity.priv,
      hsTranscript({ room: S.room, ownSid: S.sid, peerSid: p.sid, ownDtls: loc, peerDtls: rem, eph: p.eph.pubHex, name }),
    );
    if (p.gen !== gen) return;
    p.dc.send(JSON.stringify({ t: 'hs', v: 2, pub: hex(S.identity.pubRaw), name, eph: p.eph.pubHex, sig }));
    p.hsSent = true;
    renderPeers();
    await tryFinish(p, gen);
  } catch {
    failPeer(p, gen, 'falha no handshake');
  }
}

const HEX_POINT = /^04[0-9a-f]{128}$/;

async function onHandshake(p, gen, m) {
  if (
    m.v !== 2 || typeof m.name !== 'string' || typeof m.sig !== 'string' ||
    !HEX_POINT.test(m.pub ?? '') || !HEX_POINT.test(m.eph ?? '') || !p.dtls
  ) {
    failPeer(p, gen, `Handshake inválido de ${p.name}.`, true);
    return;
  }
  const pubRaw = unhex(m.pub);
  const ok = await verifyText(
    pubRaw,
    m.sig,
    hsTranscript({
      room: S.room, ownSid: p.sid, peerSid: S.sid,
      ownDtls: p.dtls.rem, peerDtls: p.dtls.loc, eph: m.eph, name: m.name,
    }),
  );
  if (p.gen !== gen) return;
  if (!ok) {
    failPeer(p, gen, `Falha ao verificar a identidade de ${p.name}. Possível interceptação — conexão encerrada.`, true);
    return;
  }
  p.idFp = await fingerprint(pubRaw);
  p.theirEph = unhex(m.eph);
  p.theirEphHex = m.eph;
  p.name = sanitizeName(m.name) || `Anônimo-${p.idFp.slice(0, 4)}`;
  p.hsRecv = true;
  renderPeers();
  await tryFinish(p, gen);
}

async function tryFinish(p, gen) {
  if (p.key || p.finishing || !p.hsSent || !p.hsRecv) return;
  p.finishing = true;
  try {
    const key = await deriveSessionKey(p.eph.priv, p.theirEph, p.eph.pubHex, p.theirEphHex, S.room);
    if (p.gen !== gen) return;
    p.key = key;
    p.state = 'secure';
    p.everSecure = true;
    p.retries = 0;
    clearTimeout(p.connTimer);
    sysMsg(`🔒 ${p.name} conectado (${shortFp(p.idFp, 3)})`);
    renderAll();
    if (isMobile()) closeDrawer();
  } catch {
    failPeer(p, gen, 'falha ao derivar a chave de sessão');
  } finally {
    p.finishing = false;
  }
}

async function onDcData(p, gen, data) {
  if (p.gen !== gen) return;
  if (typeof data === 'string') {
    if (data.length > 4096) return;
    let m;
    try { m = JSON.parse(data); } catch { return; }
    if (m && m.t === 'hs' && !p.hsRecv) await onHandshake(p, gen, m);
    return;
  }
  if (!p.key) return; // quadro binário antes de existir chave: descarta
  let plain;
  try {
    plain = await openBytes(p.key, data);
  } catch {
    return; // não autenticou (adulterado ou chave errada)
  }
  await onSecure(p, plain);
}

async function onSecure(p, plain) {
  if (plain.length < 1) return;
  const kind = plain[0];
  const body = plain.subarray(1);
  if (kind === K_JSON) {
    if (body.length > 16 * 1024) return;
    let m;
    try { m = JSON.parse(fromUtf8(body)); } catch { return; }
    switch (m?.k) {
      case 'msg': {
        const text = String(m.text ?? '').slice(0, 4000);
        if (text) {
          const id = /^[0-9a-f]{12}$/.test(String(m.id)) ? m.id : undefined;
          const r = m.re && typeof m.re === 'object' && /^[0-9a-f]{12}$/.test(String(m.re.id))
            ? { id: m.re.id, name: sanitizeName(m.re.name) || '—', text: String(m.re.text ?? '').slice(0, 140) }
            : undefined;
          addMsg({ dir: 'received', name: p.name, text, id, re: r, from: p.sid });
          playPing();
        }
        break;
      }
      case 'del': {
        // só o autor (mesma sessão cifrada) pode apagar a própria mensagem
        const id = String(m.id ?? '');
        if (!/^[0-9a-f]{12}$/.test(id)) break;
        const w = [...msgsEl.querySelectorAll('.msg[data-mid]')].find((n) => n.dataset.mid === id && n.dataset.from === p.sid);
        if (w) tombstone(w);
        break;
      }
      case 'name': {
        const n = sanitizeName(m.name);
        if (n && n !== p.name) {
          sysMsg(`${p.name} agora é ${n}`);
          p.name = n;
          renderAll();
        }
        break;
      }
      case 'file':
        onFileStart(p, m);
        break;
      default:
        break;
    }
  } else if (kind === K_FILE) {
    onFileChunk(p, body);
  }
}

async function sendSecure(p, kind, bytes) {
  const dc = p.dc;
  if (!p.key || !dc || dc.readyState !== 'open') throw new Error('sem canal seguro');
  const plain = new Uint8Array(1 + bytes.length);
  plain[0] = kind;
  plain.set(bytes, 1);
  dc.send(await sealBytes(p.key, plain));
}

const sendJson = (p, obj) => sendSecure(p, K_JSON, utf8(JSON.stringify(obj)));

// ───────────────────────── envio de mensagens ─────────────────────────
async function sendMessage() {
  const input = $('msgInput');
  const text = input.value.trim();
  if (!text) return;
  const targets = securePeers();
  if (!targets.length) {
    toast('Ninguém conectado com segurança ainda.', 'err');
    return;
  }
  const id = newMid();
  const results = await Promise.allSettled(targets.map((p) => sendJson(p, { k: 'msg', text, id, re: replyTo || undefined })));
  const delivered = results.filter((r) => r.status === 'fulfilled').length;
  if (!delivered) {
    toast('Não foi possível entregar a mensagem.', 'err');
    return;
  }
  addMsg({ dir: 'sent', text, to: delivered, total: S.peers.size, id, re: replyTo || undefined });
  setReply(null);
  input.value = '';
  autoH(input);
}

// ───────────────────────── arquivos ─────────────────────────
function waitDrain(dc) {
  return new Promise((resolve) => {
    const check = () => {
      if (dc.readyState !== 'open' || dc.bufferedAmount <= HIGH_WATER) return resolve();
      let t;
      const done = () => {
        dc.removeEventListener('bufferedamountlow', done);
        clearTimeout(t);
        check();
      };
      t = setTimeout(done, 400);
      dc.addEventListener('bufferedamountlow', done, { once: true });
      return undefined;
    };
    check();
  });
}

async function sendFile(file) {
  if (!file) return;
  if (file.size < 1) return toast('Arquivo vazio.', 'err');
  if (file.size > MAX_FILE) return toast('Arquivo muito grande (máx. 100 MB).', 'err');
  const targets = securePeers();
  if (!targets.length) return toast('Ninguém conectado com segurança ainda.', 'err');

  const id = hex(randomBytes(16));
  const idBytes = unhex(id);
  const chunks = Math.ceil(file.size / CHUNK);
  const name = sanitizeFileName(file.name);
  const ui = fileBubble({ dir: 'sent', name, size: file.size, label: 'Preparando…' });

  const started = [];
  for (const p of targets) {
    try {
      await sendJson(p, { k: 'file', id, name, size: file.size, chunks });
      started.push(p);
    } catch { /* este destinatário falhou */ }
  }
  if (!started.length) {
    ui.fail('⚠️ Não foi possível iniciar o envio');
    return undefined;
  }

  let sent = 0;
  const total = chunks * started.length;
  const okPeers = await Promise.all(
    started.map(async (p) => {
      try {
        for (let i = 0; i < chunks; i += 1) {
          const data = new Uint8Array(await file.slice(i * CHUNK, (i + 1) * CHUNK).arrayBuffer());
          const body = new Uint8Array(20 + data.length);
          body.set(idBytes, 0);
          new DataView(body.buffer).setUint32(16, i);
          body.set(data, 20);
          await waitDrain(p.dc);
          await sendSecure(p, K_FILE, body);
          sent += 1;
          ui.progress(sent / total, `Enviando… ${Math.round((sent / total) * 100)}%`);
        }
        return true;
      } catch {
        return false;
      }
    }),
  );
  const ok = okPeers.filter(Boolean).length;
  if (ok === started.length) ui.done(`✅ Enviado a ${ok} participante${ok === 1 ? '' : 's'}`);
  else ui.fail(`⚠️ Entregue a ${ok} de ${started.length}`);
  return undefined;
}

function onFileStart(p, m) {
  const id = String(m.id ?? '');
  const size = Number(m.size);
  const chunks = Number(m.chunks);
  if (
    !/^[0-9a-f]{32}$/.test(id) || !Number.isInteger(size) || size < 1 || size > MAX_FILE ||
    chunks !== Math.ceil(size / CHUNK) || p.inFiles.has(id) || p.inFiles.size >= MAX_INBOUND_FILES
  ) return;
  const name = sanitizeFileName(m.name);
  const ui = fileBubble({ dir: 'received', name, size, from: p.name, label: 'Recebendo… 0%' });
  playPing();
  p.inFiles.set(id, { name, size, chunks, parts: new Array(chunks), got: 0, bytes: 0, ui });
}

function onFileChunk(p, body) {
  if (body.length < 20) return;
  const id = hex(body.subarray(0, 16));
  const f = p.inFiles.get(id);
  if (!f) return;
  const idx = new DataView(body.buffer, body.byteOffset + 16, 4).getUint32(0);
  const data = body.subarray(20);
  if (idx >= f.chunks || f.parts[idx] || data.length > CHUNK) return;
  f.parts[idx] = data;
  f.got += 1;
  f.bytes += data.length;
  if (f.bytes > f.size) {
    f.ui.fail('⚠️ Arquivo inconsistente');
    p.inFiles.delete(id);
    return;
  }
  const frac = f.got / f.chunks;
  f.ui.progress(frac, `Recebendo… ${Math.round(frac * 100)}%`);
  if (f.got === f.chunks) {
    p.inFiles.delete(id);
    if (f.bytes !== f.size) {
      f.ui.fail('⚠️ Arquivo inconsistente');
      return;
    }
    const blob = new Blob(f.parts, { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    f.ui.done('✅ Recebido');
    f.ui.download(url, blob);
    toast(`📥 ${f.name} recebido`);
  }
}

const NATIVE_MAX = 30 * 1024 * 1024;
const NATIVE_SLICE = 384 * 1024; // múltiplo de 3 → base64 sem preenchimento no meio

/** Envia o arquivo recebido ao app nativo (Expo) em pedaços, para salvar/compartilhar. */
async function saveViaNative(blob, name) {
  try {
    if (blob.size > NATIVE_MAX) {
      toast('No app, o limite para salvar é 30 MB. Use o navegador ou o desktop.', 'err');
      return;
    }
    const id = hex(randomBytes(8));
    const n = Math.max(1, Math.ceil(blob.size / NATIVE_SLICE));
    const post = (o) => window.ReactNativeWebView.postMessage(JSON.stringify({ kslink: 1, ...o }));
    post({ t: 'save-start', id, name, n });
    for (let i = 0; i < n; i += 1) {
      const part = blob.slice(i * NATIVE_SLICE, (i + 1) * NATIVE_SLICE);
      const d = await new Promise((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(String(r.result).split(',')[1] ?? '');
        r.onerror = () => reject(r.error);
        r.readAsDataURL(part);
      });
      post({ t: 'save-chunk', id, i, d });
    }
  } catch {
    toast('Não foi possível salvar o arquivo.', 'err');
  }
}

function abortInbound(p, why) {
  for (const f of p.inFiles.values()) f.ui.fail(`⚠️ ${why}`);
  p.inFiles.clear();
}

// ───────────────────────── identidade / backup / servidor ─────────────────────────
function downloadText(filename, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = el('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

async function doExport() {
  try {
    const text = await exportBackup(S.identity, $('bkPass').value);
    downloadText('kslink-identidade.json', text);
    $('bkPass').value = '';
    toast('Backup exportado. Guarde o arquivo e a senha.');
  } catch (e) {
    toast(e.message || 'Falha ao exportar.', 'err');
  }
}

async function doImport(file) {
  if (!file) return;
  if (!window.confirm('Substituir a identidade deste navegador? A atual será perdida se você não tiver backup dela.')) return;
  try {
    const identity = await importBackup(await file.text(), $('bkPass').value);
    if (!saveIdentity(identity)) throw new Error('Não foi possível salvar neste navegador.');
    toast('Identidade importada. Recarregando…');
    setTimeout(() => location.reload(), 900);
  } catch (e) {
    toast(e.message || 'Falha ao importar.', 'err');
  }
}

function saveServer() {
  const v = $('serverInput').value.trim();
  const prev = getServer();
  setServer(v);
  try {
    serverUrl();
  } catch (e) {
    setServer(prev);
    toast(e.message, 'err');
    return;
  }
  S.iceLoaded = false;
  toast(v ? 'Servidor salvo. Vale para a próxima sala.' : 'Usando o servidor deste site.');
}

// ───────────────────────── inicialização ─────────────────────────
function bindEvents() {
  $('menuBtn').addEventListener('click', () => $('sidebar').classList.toggle('open'));
  $('closeBtn').addEventListener('click', closeDrawer);
  $('overlay').addEventListener('click', closeDrawer);

  $('nameInput').addEventListener('change', () => {
    commitName();
    for (const p of securePeers()) sendJson(p, { k: 'name', name: S.name }).catch(() => {});
    renderPeers();
  });

  $('btnCreate').addEventListener('click', () => enterRoom(newRoomCode()));
  $('btnJoin').addEventListener('click', () => enterRoom($('roomInput').value));
  $('roomInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') enterRoom($('roomInput').value);
  });
  $('btnCopyLink').addEventListener('click', () => copyText($('roomLink').value, 'Link copiado!'));
  $('roomLink').addEventListener('focus', (e) => e.target.select());
  $('btnLeave').addEventListener('click', leaveRoom);

  $('btnCopyFp').addEventListener('click', () => copyText(S.identity.fp, 'Impressão digital copiada!'));
  $('btnExport').addEventListener('click', doExport);
  $('btnImport').addEventListener('click', () => $('fileImport').click());
  $('fileImport').addEventListener('change', (e) => {
    const f = e.target.files[0];
    e.target.value = '';
    doImport(f);
  });
  $('btnSaveServer').addEventListener('click', saveServer);

  renderSoundBtn();
  $('soundBtn').addEventListener('click', () => {
    soundOn = !soundOn;
    try { localStorage.setItem('kslink.sound', soundOn ? 'on' : 'off'); } catch { /* ok */ }
    renderSoundBtn();
    if (soundOn) { unlockAudio(); playPing(); }
  });
  ['pointerdown', 'keydown'].forEach((ev) => document.addEventListener(ev, unlockAudio, { once: true, passive: true }));
  $('replyCancel').addEventListener('click', () => setReply(null));
  $('sendBtn').addEventListener('click', sendMessage);
  $('msgInput').addEventListener('input', (e) => autoH(e.target));
  $('msgInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      sendMessage();
    }
  });
  $('attachBtn').addEventListener('click', () => $('fileInput').click());
  $('fileInput').addEventListener('change', (e) => {
    const f = e.target.files[0];
    e.target.value = '';
    sendFile(f);
  });

  const wake = () => {
    if (S.wantRoom && !S.ws) {
      S.retry = 0;
      connectWs();
    }
  };
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') wake();
  });
  window.addEventListener('online', wake);

  // Mantém o servidor ativo em hospedagens gratuitas que hibernam sem tráfego.
  setInterval(() => {
    if (S.ws?.readyState === 1) S.ws.send('{"t":"ping"}');
  }, KEEPALIVE_MS);
}

async function init() {
  const { identity, persisted } = await loadOrCreateIdentity();
  S.identity = identity;
  const saved = sanitizeName(getName());
  S.name = saved || `Anônimo-${identity.fp.slice(0, 4)}`;
  $('nameInput').value = saved;
  $('myFp').textContent = shortFp(identity.fp, 8);
  $('serverInput').value = getServer();
  bindEvents();
  setNet('off');
  renderAll();

  if (!persisted) {
    toast('Não foi possível salvar a identidade neste navegador (modo privado?). Ela vale só até fechar a página.', 'err');
  }

  const m = /^#r=([A-Za-z0-9_-]{6,64})$/.exec(location.hash);
  if (m) {
    $('roomInput').value = m[1];
    if (saved) {
      enterRoom(m[1]);
    } else {
      openDrawer();
      $('nameInput').focus();
      toast('Digite seu nome e toque em "Entrar na sala".');
    }
  }
}

init().catch((e) => {
  console.error(e);
  toast('Falha ao iniciar. Seu navegador precisa ter suporte a Web Crypto e WebRTC.', 'err');
});
