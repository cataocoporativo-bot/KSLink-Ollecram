// Normaliza o endereço do servidor: "host", "https://host" ou "http://localhost:10000".
// Devolve a origem (sem barra final) ou null. Fora de localhost/rede local, só HTTPS.
const PRIVATE = /^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)$/;

export function normalizeServer(input) {
  let s = String(input ?? '').trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  const m = /^(https?):\/\/([^/?#\s]+)/i.exec(s);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  const authority = m[2];
  if (authority.includes('@')) return null; // sem credenciais embutidas
  const host = authority.replace(/:\d+$/, '').toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(host)) return null;
  if (scheme === 'http' && !PRIVATE.test(host)) return null;
  return `${scheme}://${authority.toLowerCase()}`;
}
