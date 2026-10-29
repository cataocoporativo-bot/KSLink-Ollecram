'use strict';
// KSLink Desktop 2.0 — janela Electron que abre o servidor KSLink.
// O cliente roda na mesma origem do servidor (WebSocket, /ice e localStorage da identidade).

const { app, BrowserWindow, shell, ipcMain, Menu, session } = require('electron');
const path = require('path');
const fs = require('fs');
const { pathToFileURL } = require('url');

// Ícone da janela/barra de tarefas (o do instalador vem de build.win.icon no package.json)
const APP_ICON = path.join(__dirname, 'assets', process.platform === 'win32' ? 'icon.ico' : 'icon.png');
const SETUP_FILE = path.join(__dirname, 'src', 'setup.html');
const SETUP_URL = pathToFileURL(SETUP_FILE).href;
let win = null;

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
}

const userCfgFile = () => path.join(app.getPath('userData'), 'config.json');

/** Aceita "host", "https://host" ou "http://localhost:10000". Devolve a origem ou null. */
function normalizeServer(input) {
  let s = String(input ?? '').trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol === 'http:' && !loopback) return null; // fora de loopback, só HTTPS
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  return u.origin;
}

function currentServer() {
  return (
    normalizeServer(process.env.KSLINK_SERVER) ||
    normalizeServer(readJson(userCfgFile()).serverUrl) ||
    normalizeServer(readJson(path.join(__dirname, 'config.json')).serverUrl)
  );
}

function showSetup(error) {
  if (!win) return;
  const query = { saved: readJson(userCfgFile()).serverUrl || '' };
  if (error) query.erro = String(error).slice(0, 200);
  win.loadFile(SETUP_FILE, { query });
}

function openApp() {
  const server = currentServer();
  if (!server) return showSetup();
  return win.loadURL(server).catch(() => {}); // falhas chegam em did-fail-load
}

function isAllowedUrl(url) {
  if (url.startsWith(SETUP_URL)) return true;
  const server = currentServer();
  try {
    return !!server && new URL(url).origin === server;
  } catch {
    return false;
  }
}

function createWindow() {
  win = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 800,
    minHeight: 560,
    title: 'KSLink',
    icon: APP_ICON,
    backgroundColor: '#0a0a0f',
    autoHideMenuBar: true,
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  const wc = win.webContents;
  wc.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  wc.on('will-navigate', (e, url) => {
    if (isAllowedUrl(url)) return;
    e.preventDefault();
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
  });
  wc.on('did-fail-load', (_e, code, desc, url, isMainFrame) => {
    if (!isMainFrame || code === -3 || url.startsWith(SETUP_URL)) return; // -3 = cancelado
    showSetup(`Não foi possível abrir o servidor (${desc}).`);
  });
  win.on('closed', () => {
    win = null;
  });

  openApp();
}

function buildMenu() {
  const template = [
    {
      label: 'KSLink',
      submenu: [
        { label: 'Servidor…', accelerator: 'CmdOrCtrl+Shift+S', click: () => showSetup() },
        { label: 'Recarregar', accelerator: 'CmdOrCtrl+R', click: () => openApp() },
        { type: 'separator' },
        { role: 'quit', label: 'Sair' },
      ],
    },
    { role: 'editMenu', label: 'Editar' },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// Só a página de configuração local pode falar com o processo principal.
const fromSetup = (e) => !!e.senderFrame && String(e.senderFrame.url).startsWith(SETUP_URL);

ipcMain.handle('kslink:get-server', (e) => (fromSetup(e) ? readJson(userCfgFile()).serverUrl || '' : ''));

ipcMain.handle('kslink:save-server', (e, value) => {
  if (!fromSetup(e)) return { ok: false, error: 'Origem não autorizada.' };
  const origin = normalizeServer(value);
  if (!origin) return { ok: false, error: 'Endereço inválido. Use https://… (http só em localhost).' };
  try {
    fs.mkdirSync(app.getPath('userData'), { recursive: true });
    fs.writeFileSync(userCfgFile(), JSON.stringify({ serverUrl: origin }, null, 2));
  } catch {
    return { ok: false, error: 'Não foi possível salvar a configuração.' };
  }
  setImmediate(() => win?.loadURL(origin).catch(() => {}));
  return { ok: true };
});

if (!app.requestSingleInstanceLock()) {
  app.quit(); // uma instância só: evita duas janelas disputando a mesma identidade
} else {
  app.on('second-instance', () => {
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });

  app.whenReady().then(() => {
    if (process.platform === 'win32') app.setAppUserModelId('com.kslink.app'); // agrupa na barra de tarefas com o ícone do KSLink
    // Só a cópia para a área de transferência é necessária; nega o resto.
    session.defaultSession.setPermissionRequestHandler((_wc, perm, cb) => cb(perm === 'clipboard-sanitized-write'));
    session.defaultSession.setPermissionCheckHandler((_wc, perm) => perm === 'clipboard-sanitized-write');
    buildMenu();
    createWindow();
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
