// Aplica brand.json (cores, fontes, estilo e logotipos) à interface.
// Uso:  node tools/apply-brand.mjs            (lê ./brand.json)
//       node tools/apply-brand.mjs brands/laic.json
// Gera public/brand.css e ajusta as imagens/cor do tema em public/index.html.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cfgPath = process.argv[2] ? resolve(process.cwd(), process.argv[2]) : join(root, 'brand.json');
const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
const pub = (f) => join(root, 'public', f);
const fail = (m) => { console.error(`brand: ${m}`); process.exit(1); };

const HEX = /^#[0-9a-fA-F]{6}$/;
const rgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16)).join(', ');
const c = cfg.colors || {};
const need = ['bg', 'surface', 'surface2', 'border', 'accent', 'accent2', 'violet', 'danger', 'warn', 'text', 'muted', 'onAccent', 'accentHover', 'inputBg'];
for (const k of need) if (!HEX.test(c[k] || '')) fail(`cor "${k}" ausente ou inválida (use #RRGGBB)`);
if (!['cyberpunk', 'corporate'].includes(cfg.style)) fail('"style" deve ser "cyberpunk" ou "corporate"');

const q = (s) => String(s).replace(/[^\w .\-]/g, '');
let css = `/* GERADO por tools/apply-brand.mjs a partir de brand.json — não edite à mão. */\n`;
for (const f of cfg.fonts?.faces || []) {
  if (!existsSync(pub(`fonts/${f.file}`))) fail(`fonte não encontrada: public/fonts/${f.file}`);
  css += `@font-face { font-family: '${q(f.family)}'; font-weight: ${Number(f.weight) || 400}; font-style: normal; font-display: swap; src: url('fonts/${f.file}') format('woff2'); }\n`;
}
css += `:root {\n`;
const vars = { bg: 'bg', surface: 'surface', surface2: 'surface2', border: 'border', accent: 'accent', accent2: 'accent2', violet: 'violet', danger: 'danger', warn: 'warn', text: 'text', muted: 'muted', onAccent: 'on-accent', accentHover: 'accent-hover', inputBg: 'input-bg' };
for (const [k, v] of Object.entries(vars)) css += `  --${v}: ${c[k]};\n`;
for (const k of ['bg', 'surface', 'accent', 'accent2', 'violet', 'danger', 'text']) css += `  --${k}-rgb: ${rgb(c[k])};\n`;
for (const k of ['ui', 'display', 'mono']) if (cfg.fonts?.[k]) css += `  --${k}: ${cfg.fonts[k]};\n`;
css += `}\n`;

if (cfg.style === 'corporate') {
  css += `
/* estilo corporativo: sem grade, linhas de varredura, glitch, brilho neon nem cantos chanfrados */
body::before, body::after { display: none; }
body { background: var(--bg); }
* { clip-path: none !important; }
:root { --glow: none; --glow2: none; --cut: 0px; }
.logo-text { animation: none; text-shadow: none; letter-spacing: 0.04em; }
header::after { box-shadow: none; }
.btn, input[type='text'], input[type='password'], #msgInput, .bubble, .file-bubble, .peer, .e2ee-badge, .quote, .mini-btn, .send-btn, .attach-btn, .snd-btn { border-radius: 8px; }
.btn.pri:hover { filter: none; }
.dot { transform: none; border-radius: 50%; }
.brand-foot > img { width: 50%; max-width: 150px; opacity: 1; }
.empty-logo { filter: none; animation: none; }
.empty-title { text-shadow: none; letter-spacing: 0.04em; }
.sidebar { box-shadow: none; }
.sidebar.open { box-shadow: 4px 0 24px rgba(0, 0, 0, 0.18); }
.drawer-overlay { background: rgba(20, 30, 40, 0.35); }
.dot.on, .dot.connecting { box-shadow: none; }
.e2ee-badge.active { text-shadow: none; }
.sec-label, .peer-name, .logo-text, .adv summary { text-transform: none; }
`;
}
writeFileSync(pub('brand.css'), css);

// index.html é gerado a partir de tools/index.template.html (cor do tema e logotipos)
const esc = (t) => String(t).replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
const L = cfg.logos || {};
const logo = (slot) => {
  const l = L[slot];
  if (!l) return null;
  if (!existsSync(pub(l.file))) fail(`logotipo não encontrado: public/${l.file}`);
  return l;
};
const h = logo('header');
const f = logo('foot');
const e = logo('empty');
const cr = logo('credit');
const out = readFileSync(join(root, 'tools/index.template.html'), 'utf8')
  .replace('{{THEME_COLOR}}', cfg.themeColor || c.bg)
  .replace('{{LOGO_HEADER}}', h
    ? `<div class="by">${h.label ? `\n      <span class="by-lbl">${esc(h.label)}</span>` : ''}\n      <img class="by-img" src="${esc(h.file)}" alt="${esc(h.alt || '')}">\n    </div>`
    : '')
  .replace('{{LOGO_FOOT}}', f || cr
    ? `<div class="brand-foot">${f ? `<img src="${esc(f.file)}" alt="${esc(f.alt || '')}">` : ''}${cr ? `<div class="brand-credit">${cr.label ? `<span>${esc(cr.label)}</span>` : ''}<img src="${esc(cr.file)}" alt="${esc(cr.alt || '')}"></div>` : ''}</div>`
    : '')
  .replace('{{LOGO_EMPTY}}', e ? `<img class="empty-logo" src="${esc(e.file)}" alt="${esc(e.alt || '')}">` : '');
writeFileSync(pub('index.html'), out);
console.log(`brand aplicado: estilo ${cfg.style}, ${cfg.fonts?.faces?.length || 0} fonte(s) própria(s)`);
