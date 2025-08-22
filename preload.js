const { contextBridge, ipcRenderer } = require('electron');

const validChannels = [
  'password-verify',
  'password-set',
  'whitelist-get',
  'whitelist-update',
  'toggle-block-files-app',
  'blocking-status-request',
  'password-change',
  'request-logs',
  'login-success',
  'disable-blocking',
  'enable-blocking',
  'blocking-status-changed'
];

contextBridge.exposeInMainWorld('electronAPI', {
  send: (channel, data) => {
    if (validChannels.includes(channel)) {
      ipcRenderer.send(channel, data);
    }
  },
  invoke: (channel, data) => {
    if (validChannels.includes(channel)) {
      return ipcRenderer.invoke(channel, data);
    }
    return Promise.reject(new Error('Invalid IPC channel'));
  },
  on: (channel, func) => {
    if (validChannels.includes(channel)) {
      ipcRenderer.on(channel, (event, ...args) => func(...args));
    }
  },
  once: (channel, func) => {
    if (validChannels.includes(channel)) {
      ipcRenderer.once(channel, (event, ...args) => func(...args));
    }
  }
});
