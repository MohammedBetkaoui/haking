const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('guardian', {
  expand:     () => ipcRenderer.send('bar:expand'),
  collapse:   () => ipcRenderer.send('bar:collapse'),
  move:       (screenX, screenY, offsetX, offsetY) => ipcRenderer.send('bar:move', { screenX, screenY, offsetX, offsetY }),
  systemInfo: () => ipcRenderer.invoke('system:info'),
});
