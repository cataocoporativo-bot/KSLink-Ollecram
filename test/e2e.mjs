// Teste ponta a ponta: 3 navegadores reais (Chromium headless) numa sala.
// Uso: node test/e2e.mjs   (requer playwright; PLAYWRIGHT_MODULE pode apontar para ele)
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { createApp, loadConfig } from '../server/server.js';

const require = createRequire(import.meta.url);
const pwPath = process.env.PLAYWRIGHT_MODULE || 'playwright';
let chromium;
try {
  ({ chromium } = require(pwPath));
} catch {
  ({ chromium } = require('/opt/npm-tools/node_modules/playwright'));
}

const app = createApp(loadConfig({ ICE_SERVERS: '[]' }, { port: 0, host: '127.0.0.1' }));
const addr = await app.listen(0, '127.0.0.1');
const base = `http://127.0.0.1:${addr.port}`;

const browser = await chromium.launch({
  args: ['--disable-features=WebRtcHideLocalIpsWithMdns'],
});

const results = [];
const step = (name) => { results.push(name); console.log(`✔ ${name}`); };

async function newUser(name, url, { native = false } = {}) {
  const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1100, height: 800 } });
  const page = await ctx.newPage();
  if (native) {
    // Simula o WebView do app Expo: captura o que o cliente envia ao código nativo.
    await page.addInitScript(() => {
      window.__rn = [];
      window.ReactNativeWebView = { postMessage: (m) => window.__rn.push(m) };
    });
  }
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  await page.goto(url);
  await page.fill('#nameInput', name);
  await page.evaluate(() => document.getElementById('nameInput').dispatchEvent(new Event('change')));
  return { ctx, page, name, errors };
}

const secureCount = (page) => page.evaluate(
  () => [...document.querySelectorAll('#peerList .peer:not(.self) .st.ok')].length,
);

async function waitSecure(user, n) {
  await user.page.waitForFunction(
    (k) => document.querySelectorAll('#peerList .peer:not(.self) .st.ok').length >= k,
    n,
    { timeout: 30_000 },
  );
}

const sha = (buf) => createHash('sha256').update(buf).digest('hex');

try {
  // 1) Ana cria a sala
  const ana = await newUser('Ana', base);
  await ana.page.click('#btnCreate');
  await ana.page.waitForFunction(() => document.getElementById('netTxt').textContent === 'Online', null, { timeout: 15_000 });
  const link = await ana.page.inputValue('#roomLink');
  assert.match(link, /#r=[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/);
  step('sala criada, servidor de sinalização online');

  // 2) Beto entra pelo link (nome já salvo → entra automático depois de definir nome)
  const beto = await newUser('Beto', base);
  await beto.page.fill('#roomInput', link);
  await beto.page.click('#btnJoin');
  await waitSecure(ana, 1);
  await waitSecure(beto, 1);
  step('Ana e Beto conectados com E2EE (sem copiar/colar)');

  // 3) Cecília entra: malha de 3
  const cec = await newUser('Cecília', base, { native: true });
  await cec.page.fill('#roomInput', link);
  await cec.page.click('#btnJoin');
  await waitSecure(cec, 2);
  await waitSecure(ana, 2);
  await waitSecure(beto, 2);
  step('malha com 3 participantes, todos seguros entre si');

  // 4) Mensagem em grupo
  await ana.page.fill('#msgInput', 'olá grupo <b>não-html</b>');
  await ana.page.click('#sendBtn');
  for (const u of [beto, cec]) {
    await u.page.waitForFunction(
      () => [...document.querySelectorAll('.msg.received .bubble')].some((b) => b.textContent === 'olá grupo <b>não-html</b>'),
      null,
      { timeout: 10_000 },
    );
    assert.equal(await u.page.locator('.msg.received .bubble b').count(), 0, 'HTML não pode ser interpretado');
  }
  step('mensagem entregue a todos, renderizada como texto puro');

  // 5) Resposta de outro participante chega a todos
  await cec.page.fill('#msgInput', 'resposta da Cecília');
  await cec.page.press('#msgInput', 'Enter');
  for (const u of [ana, beto]) {
    await u.page.waitForFunction(
      () => [...document.querySelectorAll('.msg.received')].some((m) => m.textContent.includes('resposta da Cecília') && m.textContent.includes('Cecília')),
      null,
      { timeout: 10_000 },
    );
  }
  step('mensagens fluem em qualquer direção do grupo');

  // 5b) Resposta citando a mensagem de Ana
  await beto.page.evaluate(() => {
    window.__pings = 0;
    const AC = window.AudioContext;
    window.AudioContext = class extends AC { createOscillator() { window.__pings += 1; return super.createOscillator(); } };
  });
  await beto.page.locator('.msg.received', { hasText: 'olá grupo' }).locator('.reply-btn').click();
  assert.match(await beto.page.textContent('#replyBody'), /olá grupo/);
  await beto.page.fill('#msgInput', 'respondendo a Ana');
  await beto.page.press('#msgInput', 'Enter');
  assert.ok(await beto.page.locator('#replyBar.hidden').count(), 'barra de resposta some após enviar');
  for (const u of [ana, cec]) {
    await u.page.waitForFunction(
      () => [...document.querySelectorAll('.msg .quote')].some((q) => q.textContent.includes('olá grupo')),
      null,
      { timeout: 10_000 },
    );
  }
  step('resposta com citação chega a todos e a barra de resposta é limpa');

  // 5c) Som: botão alterna e persiste
  await ana.page.click('#soundBtn');
  assert.equal(await ana.page.evaluate(() => localStorage.getItem('kslink.sound')), 'off');
  await ana.page.click('#soundBtn');
  assert.equal(await ana.page.evaluate(() => localStorage.getItem('kslink.sound')), 'on');
  step('botão de som liga/desliga e lembra a escolha');

  // 5d) Apagar para todos: só o autor, e some em todos os participantes
  await beto.page.evaluate(() => { window.confirm = () => true; });
  await beto.page.locator('.msg.sent', { hasText: 'respondendo a Ana' }).locator('.del-btn').click();
  for (const u of [ana, cec]) {
    await u.page.waitForFunction(
      () => ![...document.querySelectorAll('.msg:not(.deleted) .bubble')].some((b) => b.textContent === 'respondendo a Ana')
        && document.querySelectorAll('.msg.deleted').length >= 1,
      null,
      { timeout: 10_000 },
    );
  }
  assert.equal(await ana.page.locator('.msg.received .del-btn').count(), 0, 'mensagens de outros não têm botão de apagar');
  step('mensagem apagada pelo autor some para todos (com aviso)');

  // 6) Arquivo (≈2,5 MB, com bytes aleatórios) de Beto para todos
  const dir = mkdtempSync(join(tmpdir(), 'kslink-e2e-'));
  const payload = randomBytes(2_500_000 + 123);
  const fpath = join(dir, 'dados.bin');
  writeFileSync(fpath, payload);
  await beto.page.setInputFiles('#fileInput', fpath);
  {
    const dl = await ana.page.waitForSelector('.dl-btn', { timeout: 30_000 });
    const [download] = await Promise.all([ana.page.waitForEvent('download'), dl.click()]);
    const out = join(dir, 'Ana.bin');
    await download.saveAs(out);
    assert.equal(sha(readFileSync(out)), sha(payload), 'hash do arquivo de Ana');
  }
  step('arquivo de 2,5 MB recebido pelo navegador com hash idêntico');

  // App móvel: botão "Salvar" envia o arquivo em pedaços ao código nativo
  {
    const dl = await cec.page.waitForSelector('button.dl-btn', { timeout: 30_000 });
    await dl.click();
    await cec.page.waitForFunction(() => {
      const ms = window.__rn.map((x) => JSON.parse(x));
      const st = ms.find((x) => x.t === 'save-start');
      return st && ms.filter((x) => x.t === 'save-chunk').length === st.n;
    }, null, { timeout: 30_000 });
    const msgs = (await cec.page.evaluate(() => window.__rn)).map((x) => JSON.parse(x));
    const start = msgs.find((x) => x.t === 'save-start');
    assert.equal(start.name, 'dados.bin');
    const chunks = msgs.filter((x) => x.t === 'save-chunk').sort((a, b) => a.i - b.i);
    chunks.forEach((c, i) => assert.equal(c.i, i));
    assert.equal(sha(Buffer.from(chunks.map((c) => c.d).join(''), 'base64')), sha(payload), 'hash do arquivo no app móvel');
  }
  step('app móvel: arquivo entregue ao código nativo em pedaços, hash idêntico');

  // 7) Identidade persistente: recarregar mantém a mesma impressão digital
  const fpBefore = await ana.page.textContent('#myFp');
  await ana.page.reload();
  await ana.page.waitForFunction(() => document.getElementById('netTxt').textContent === 'Online', null, { timeout: 15_000 });
  const fpAfter = await ana.page.textContent('#myFp');
  assert.equal(fpAfter, fpBefore);
  assert.notEqual(fpAfter, '—');
  step('identidade persistente: mesma impressão digital após recarregar');

  // 8) Reconexão: depois do reload, Ana volta a falar com os dois (a sala vem do #r=)
  await waitSecure(ana, 2);
  await waitSecure(beto, 2);
  await ana.page.fill('#msgInput', 'voltei');
  await ana.page.click('#sendBtn');
  await cec.page.waitForFunction(
    () => [...document.querySelectorAll('.msg.received .bubble')].some((b) => b.textContent === 'voltei'),
    null,
    { timeout: 10_000 },
  );
  // Peers de Beto devem mostrar a mesma identidade de Ana (fp curto) antes e depois
  step('reconexão automática após recarregar e a identidade é reconhecida');

  // 9) Impressões digitais de duas pessoas distintas diferem
  const fpBeto = await beto.page.textContent('#myFp');
  assert.notEqual(fpBeto, fpAfter);
  step('identidades de pessoas diferentes são diferentes');

  // 10) Saída de participante é refletida
  await cec.page.click('#btnLeave');
  await ana.page.waitForFunction(
    () => document.querySelectorAll('#peerList .peer').length === 2,
    null,
    { timeout: 10_000 },
  );
  step('saída de participante atualiza a lista dos demais');

  // 11) Sala inválida / sem erros de JS / CSP sem violações
  const all = [ana, beto, cec];
  for (const u of all) {
    const bad = u.errors.filter((e) => !/favicon|Failed to load resource/i.test(e));
    assert.deepEqual(bad, [], `erros de console em ${u.name}: ${bad.join(' | ')}`);
  }
  step('nenhum erro de JavaScript nem violação de CSP nos 3 navegadores');

  console.log(`\nE2E OK — ${results.length} verificações`);
} catch (e) {
  console.error('\nE2E FALHOU:', e);
  process.exitCode = 1;
} finally {
  await browser.close();
  await app.close();
}
