const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // App info
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
  
  // File operations
  showSaveDialog: (options) => ipcRenderer.invoke('show-save-dialog', options),
  showOpenDialog: (options) => ipcRenderer.invoke('show-open-dialog', options),
  
  // Menu events
  onMenuNewAnalysis: (callback) => ipcRenderer.on('menu-new-analysis', callback),
  onMenuExportResults: (callback) => ipcRenderer.on('menu-export-results', callback),
  onMenuToggleSystem: (callback) => ipcRenderer.on('menu-toggle-system', callback),
  onMenuClearHistory: (callback) => ipcRenderer.on('menu-clear-history', callback),
  onMenuProtectionLevel: (callback) => ipcRenderer.on('menu-protection-level', callback),
  onMenuSwitchTab: (callback) => ipcRenderer.on('menu-switch-tab', callback),
  
  // Remove listeners
  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel),
  
  // Platform info
  platform: process.platform,
  
  // Node.js APIs (limited exposure for security)
  path: {
    join: (...args) => require('path').join(...args),
    dirname: (path) => require('path').dirname(path),
    basename: (path) => require('path').basename(path)
  }
});

// Security: Remove Node.js globals in renderer process
delete window.require;
delete window.exports;
delete window.module;