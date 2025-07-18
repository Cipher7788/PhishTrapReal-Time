import { useEffect, useState } from 'react';

interface ElectronAPI {
  getAppVersion: () => Promise<string>;
  showSaveDialog: (options: any) => Promise<any>;
  showOpenDialog: (options: any) => Promise<any>;
  onMenuNewAnalysis: (callback: () => void) => void;
  onMenuExportResults: (callback: (event: any, filePath: string) => void) => void;
  onMenuToggleSystem: (callback: () => void) => void;
  onMenuClearHistory: (callback: () => void) => void;
  onMenuProtectionLevel: (callback: (event: any, level: string) => void) => void;
  onMenuSwitchTab: (callback: (event: any, tab: string) => void) => void;
  removeAllListeners: (channel: string) => void;
  platform: string;
}

declare global {
  interface Window {
    electronAPI?: ElectronAPI;
  }
}

export const useElectron = () => {
  const [isElectron, setIsElectron] = useState(false);
  const [appVersion, setAppVersion] = useState<string>('');

  useEffect(() => {
    const checkElectron = async () => {
      if (window.electronAPI) {
        setIsElectron(true);
        try {
          const version = await window.electronAPI.getAppVersion();
          setAppVersion(version);
        } catch (error) {
          console.error('Failed to get app version:', error);
        }
      }
    };

    checkElectron();
  }, []);

  const exportResults = async (data: any) => {
    if (!window.electronAPI) return;

    try {
      const result = await window.electronAPI.showSaveDialog({
        defaultPath: 'phishtrap-results.json',
        filters: [
          { name: 'JSON Files', extensions: ['json'] },
          { name: 'All Files', extensions: ['*'] }
        ]
      });

      if (!result.canceled && result.filePath) {
        // In a real implementation, you would write the file here
        // For now, we'll just download it as a blob
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'phishtrap-results.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Failed to export results:', error);
    }
  };

  const setupMenuHandlers = (handlers: {
    onNewAnalysis?: () => void;
    onToggleSystem?: () => void;
    onClearHistory?: () => void;
    onProtectionLevel?: (level: string) => void;
    onSwitchTab?: (tab: string) => void;
  }) => {
    if (!window.electronAPI) return;

    if (handlers.onNewAnalysis) {
      window.electronAPI.onMenuNewAnalysis(handlers.onNewAnalysis);
    }

    if (handlers.onToggleSystem) {
      window.electronAPI.onMenuToggleSystem(handlers.onToggleSystem);
    }

    if (handlers.onClearHistory) {
      window.electronAPI.onMenuClearHistory(handlers.onClearHistory);
    }

    if (handlers.onProtectionLevel) {
      window.electronAPI.onMenuProtectionLevel((_, level) => handlers.onProtectionLevel!(level));
    }

    if (handlers.onSwitchTab) {
      window.electronAPI.onMenuSwitchTab((_, tab) => handlers.onSwitchTab!(tab));
    }

    // Setup export handler
    window.electronAPI.onMenuExportResults(async (_, filePath) => {
      // This would be handled by the parent component
      console.log('Export to:', filePath);
    });
  };

  const cleanup = () => {
    if (!window.electronAPI) return;

    window.electronAPI.removeAllListeners('menu-new-analysis');
    window.electronAPI.removeAllListeners('menu-export-results');
    window.electronAPI.removeAllListeners('menu-toggle-system');
    window.electronAPI.removeAllListeners('menu-clear-history');
    window.electronAPI.removeAllListeners('menu-protection-level');
    window.electronAPI.removeAllListeners('menu-switch-tab');
  };

  return {
    isElectron,
    appVersion,
    exportResults,
    setupMenuHandlers,
    cleanup,
    platform: window.electronAPI?.platform || 'web'
  };
};