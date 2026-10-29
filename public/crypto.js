// KSLink 2.0 — módulo de criptografia (Web Crypto API, sem dependências).
// Funciona no navegador e no Node >= 20 (usado nos testes).
//
// Modelo:
//   • Identidade de longo prazo: par ECDSA P-256. A "impressão digital" (fingerprint)
//     é o SHA-256 da chave pública — é o que as pessoas comparam para se verificar.
//   • Cada conexão par a par faz um handshake pelo DataChannel: cada lado envia uma
//     chave efêmera ECDH P-256 ASSINADA com a identidade. A assinatura cobre também
//     os fingerprints DTLS de ambos os lados (vínculo ao canal): se o servidor de
//     sinalização tentar intermediar a conexão (MITM), a verificação falha.
//   • A chave de sessão AES-GCM 256 sai de ECDH + HKDF (sigilo perfeito por conexão).

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };

// ───────────── utilidades ─────────────
export const utf8 = (s) => enc.encode(s);
export const fromUtf8 = (b) => dec.decode(b);

export function hex(buf) {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

export function unhex(s) {
  if (typeof s !== 'string' || s.length % 2 !== 0 || /[^0-9a-f]/i.test(s)) throw new Error('hex inválido');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

function b64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

// ───────────── identidade ─────────────
const cleanJwk = (j) => ({ kty: j.kty, crv: j.crv, x: j.x, y: j.y, d: j.d });

export async function fingerprint(pubRaw) {
  return hex(await subtle.digest('SHA-256', pubRaw));
}

/** 6 grupos de 4 hex (96 bits) — suficiente para comparar de viva voz. */
export function shortFp(fp, groups = 6) {
  return fp.slice(0, groups * 4).toUpperCase().match(/.{4}/g).join(':');
}

export async function loadIdentity(jwk) {
  const j = cleanJwk(jwk ?? {});
  if (j.kty !== 'EC' || j.crv !== 'P-256' || !j.x || !j.y || !j.d) throw new Error('identidade inválida');
  const priv = await subtle.importKey('jwk', j, ECDSA, false, ['sign']);
  const pub = await subtle.importKey('jwk', { kty: j.kty, crv: j.crv, x: j.x, y: j.y }, ECDSA, true, ['verify']);
  const pubRaw = new Uint8Array(await subtle.exportKey('raw', pub));
  return { jwk: j, priv, pubRaw, fp: await fingerprint(pubRaw) };
}

export async function generateIdentity() {
  const kp = await subtle.generateKey(ECDSA, true, ['sign', 'verify']);
  return loadIdentity(await subtle.exportKey('jwk', kp.privateKey));
}

export async function signText(priv, text) {
  return hex(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, utf8(text)));
}

export async function verifyText(pubRaw, sigHex, text) {
  try {
    const key = await subtle.importKey('raw', pubRaw, ECDSA, false, ['verify']);
    return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, unhex(sigHex), utf8(text));
  } catch {
    return false;
  }
}

// ───────────── handshake ─────────────
/** Fingerprint DTLS (linha `a=fingerprint:` do SDP), normalizado. */
export function dtlsFingerprint(sdp) {
  const m = /^a=fingerprint:(\S+)[ \t]+([0-9A-Fa-f:]+)/m.exec(String(sdp));
  if (!m) throw new Error('SDP sem fingerprint DTLS');
  return `${m[1]} ${m[2]}`.toLowerCase();
}

/**
 * Texto assinado no handshake. `own*` = quem assina; `peer*` = o outro lado,
 * sempre do ponto de vista de quem assina. Quem verifica inverte os papéis usando
 * o que ELE mesmo observou (seu SDP local e remoto) — por isso um MITM no SDP quebra.
 */
export function hsTranscript({ room, ownSid, peerSid, ownDtls, peerDtls, eph, name }) {
  return ['KSLINK-HS', 'v2', room, ownSid, peerSid, ownDtls, peerDtls, eph, JSON.stringify(name)].join('|');
}

export async function generateEphemeral() {
  const kp = await subtle.generateKey(ECDH, false, ['deriveBits']);
  const pubRaw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  return { priv: kp.privateKey, pubRaw, pubHex: hex(pubRaw) };
}

export async function deriveSessionKey(myPriv, theirEphRaw, myEphHex, theirEphHex, room) {
  const theirPub = await subtle.importKey('raw', theirEphRaw, ECDH, false, []);
  const bits = await subtle.deriveBits({ name: 'ECDH', public: theirPub }, myPriv, 256);
  const hk = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  const [a, b] = [myEphHex, theirEphHex].sort();
  const salt = new Uint8Array(await subtle.digest('SHA-256', utf8(`${a}|${b}`)));
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: utf8(`KSLink v2 session|${room}`) },
    hk,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// ───────────── quadros cifrados (AES-GCM, IV aleatório de 96 bits) ─────────────
export async function sealBytes(key, plain) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return out;
}

export async function openBytes(key, frame) {
  const u = frame instanceof Uint8Array ? frame : new Uint8Array(frame);
  if (u.length < 12 + 16) throw new Error('quadro curto demais');
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: u.subarray(0, 12) }, key, u.subarray(12)));
}

// ───────────── backup da identidade (protegido por senha) ─────────────
const BACKUP_ITER = 600_000;

async function pbkdf2Key(passphrase, salt, iter) {
  const base = await subtle.importKey('raw', utf8(passphrase), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function exportBackup(identity, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 8) throw new Error('A senha precisa ter ao menos 8 caracteres.');
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await pbkdf2Key(passphrase, salt, BACKUP_ITER);
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8(JSON.stringify({ v: 1, jwk: identity.jwk }))),
  );
  return JSON.stringify({
    app: 'kslink',
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iter: BACKUP_ITER,
    salt: b64(salt),
    iv: b64(iv),
    ct: b64(ct),
  });
}

export async function importBackup(text, passphrase) {
  let f;
  try {
    f = JSON.parse(text);
  } catch {
    throw new Error('Arquivo de backup inválido.');
  }
  if (!f || f.app !== 'kslink' || f.v !== 1 || !Number.isInteger(f.iter) || f.iter < 100_000 || f.iter > 5_000_000) {
    throw new Error('Arquivo de backup inválido.');
  }
  let plain;
  try {
    const key = await pbkdf2Key(String(passphrase ?? ''), unb64(f.salt), f.iter);
    plain = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(f.iv) }, key, unb64(f.ct));
  } catch {
    throw new Error('Senha incorreta ou arquivo corrompido.');
  }
  const body = JSON.parse(fromUtf8(new Uint8Array(plain)));
  return loadIdentity(body.jwk);
}
