'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kslink', {
  getServer: () => ipcRenderer.invoke('kslink:get-server'),
  saveServer: (url) => ipcRenderer.invoke('kslink:save-server', url),
});
