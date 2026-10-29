// KSLink 2.0 — persistência local (apenas navegador).
// Tudo fica no dispositivo: nada disso é enviado ao servidor.

import { generateIdentity, loadIdentity } from './crypto.js';

const K_ID = 'kslink.identity.v1';
const K_NAME = 'kslink.name';
const K_VERIFIED = 'kslink.verified';
const K_SERVER = 'kslink.server';

const ls = {
  get(k) {
    try {
      return localStorage.getItem(k);
    } catch {
      return null;
    }
  },
  set(k, v) {
    try {
      localStorage.setItem(k, v);
      return true;
    } catch {
      return false;
    }
  },
  del(k) {
    try {
      localStorage.removeItem(k);
    } catch {
      /* sem armazenamento */
    }
  },
};

/** Carrega a identidade salva ou cria uma nova na primeira visita. */
export async function loadOrCreateIdentity() {
  const raw = ls.get(K_ID);
  if (raw) {
    try {
      return { identity: await loadIdentity(JSON.parse(raw)), persisted: true, fresh: false };
    } catch {
      ls.set(`${K_ID}.bak`, raw); // não destrói o que existia
    }
  }
  const identity = await generateIdentity();
  const mine = JSON.stringify(identity.jwk);
  const persisted = ls.set(K_ID, mine);
  try {
    navigator.storage?.persist?.(); // pede ao navegador para não descartar o armazenamento
  } catch {
    /* opcional */
  }
  // Duas abas na primeira visita: vale a que gravou por último.
  const stored = ls.get(K_ID);
  if (persisted && stored && stored !== mine) {
    try {
      return { identity: await loadIdentity(JSON.parse(stored)), persisted: true, fresh: false };
    } catch {
      /* mantém a gerada */
    }
  }
  return { identity, persisted, fresh: true };
}

export const saveIdentity = (identity) => ls.set(K_ID, JSON.stringify(identity.jwk));

export const getName = () => ls.get(K_NAME) ?? '';
export const setName = (n) => ls.set(K_NAME, n);

export function getVerified() {
  try {
    const a = JSON.parse(ls.get(K_VERIFIED) ?? '[]');
    return new Set(Array.isArray(a) ? a.filter((x) => typeof x === 'string') : []);
  } catch {
    return new Set();
  }
}

/** Marca/desmarca uma identidade como verificada. Retorna o novo estado. */
export function toggleVerified(fp) {
  const s = getVerified();
  if (s.has(fp)) s.delete(fp);
  else s.add(fp);
  ls.set(K_VERIFIED, JSON.stringify([...s]));
  return s.has(fp);
}

export const getServer = () => ls.get(K_SERVER) ?? '';
export const setServer = (v) => (v ? ls.set(K_SERVER, v) : ls.del(K_SERVER));
