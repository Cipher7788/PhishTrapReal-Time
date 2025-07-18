import React, { useState, useEffect } from 'react';
import { Shield, Github, ExternalLink, Activity, Bug, BarChart3, Monitor, Download } from 'lucide-react';
import { RealTimeURLInput } from './components/RealTimeURLInput';
import { RealTimeAnalysisResults } from './components/RealTimeAnalysisResults';
import { ScanHistory } from './components/ScanHistory';
import { AdvancedStatistics } from './components/AdvancedStatistics';
import { SystemStatusMonitor } from './components/SystemStatusMonitor';
import { RealTimeSecurityAnalyzer } from './utils/realTimeAnalyzer';
import { AnalysisResult, ScanHistory as ScanHistoryType, SystemStatus } from './types';
import { useElectron } from './hooks/useElectron';

function App() {
  const [currentResult, setCurrentResult] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanHistoryType[]>([]);
  const [activeTab, setActiveTab] = useState<'analyze' | 'monitor' | 'history' | 'stats'>('analyze');
  const [systemStatus, setSystemStatus] = useState<SystemStatus>({
    isActive: false,
    threatsBlocked: 0,
    sitesAnalyzed: 0,
    lastActivity: Date.now(),
    protectionLevel: 'enhanced'
  });
  
  const { isElectron, appVersion, exportResults, setupMenuHandlers, cleanup } = useElectron();

  // Load data from localStorage on mount
  useEffect(() => {
    const savedHistory = localStorage.getItem('phishTrap-realtime-history');
    if (savedHistory) {
      setScanHistory(JSON.parse(savedHistory));
    }

    const savedSystemStatus = localStorage.getItem('phishTrap-system-status');
    if (savedSystemStatus) {
      setSystemStatus(JSON.parse(savedSystemStatus));
    }
    
    // Setup Electron menu handlers
    if (isElectron) {
      setupMenuHandlers({
        onNewAnalysis: () => {
          setCurrentResult(null);
          setActiveTab('analyze');
        },
        onToggleSystem: handleToggleSystem,
        onClearHistory: handleClearHistory,
        onProtectionLevel: handleChangeProtectionLevel,
        onSwitchTab: (tab) => setActiveTab(tab as any)
      });
    }
    
    return () => {
      if (isElectron) {
        cleanup();
      }
    };
  }, []);

  // Save data to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem('phishTrap-realtime-history', JSON.stringify(scanHistory));
  }, [scanHistory]);

  useEffect(() => {
    localStorage.setItem('phishTrap-system-status', JSON.stringify(systemStatus));
  }, [systemStatus]);

  // Simulate background monitoring when system is active
  useEffect(() => {
    if (!systemStatus.isActive) return;

    const interval = setInterval(() => {
      setSystemStatus(prev => ({
        ...prev,
        lastActivity: Date.now()
      }));
    }, 5000);

    return () => clearInterval(interval);
  }, [systemStatus.isActive]);

  const handleAnalyze = async (url: string) => {
    setIsLoading(true);
    setActiveTab('analyze');
    
    // Update system status
    setSystemStatus(prev => ({
      ...prev,
      sitesAnalyzed: prev.sitesAnalyzed + 1,
      lastActivity: Date.now()
    }));
    
    try {
      const result = await RealTimeSecurityAnalyzer.analyzeWebsite(url);
      setCurrentResult(result);
      
      // Add to history
      const historyItem: ScanHistoryType = {
        id: Date.now().toString(),
        url: result.url,
        threatLevel: result.threatLevel,
        timestamp: result.timestamp,
        score: result.score,
        vulnerabilities: result.vulnerabilities.length,
        realTimeThreats: result.realTimeThreats.length,
        responseTime: result.responseTime || 0
      };
      
      setScanHistory(prev => [historyItem, ...prev.slice(0, 49)]); // Keep last 50 scans

      // Update threats blocked if malicious content detected
      if (result.threatLevel === 'malicious' || result.threatLevel === 'critical') {
        setSystemStatus(prev => ({
          ...prev,
          threatsBlocked: prev.threatsBlocked + 1
        }));
      }
    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleToggleSystem = () => {
    setSystemStatus(prev => ({
      ...prev,
      isActive: !prev.isActive,
      lastActivity: Date.now()
    }));
  };

  const handleChangeProtectionLevel = (level: 'basic' | 'enhanced' | 'maximum') => {
    setSystemStatus(prev => ({
      ...prev,
      protectionLevel: level,
      lastActivity: Date.now()
    }));
  };

  const handleClearHistory = () => {
    setScanHistory([]);
    localStorage.removeItem('phishTrap-realtime-history');
  };

  const handleSelectScan = (url: string) => {
    if (systemStatus.isActive) {
      handleAnalyze(url);
    }
  };
  
  const handleExportResults = async () => {
    const exportData = {
      timestamp: Date.now(),
      systemStatus,
      scanHistory,
      currentResult,
      appVersion: isElectron ? appVersion : '1.0.0-web'
    };
    
    if (isElectron) {
      await exportResults(exportData);
    } else {
      // Web fallback
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'phishtrap-results.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };

  const tabs = [
    { id: 'analyze', label: 'Real-Time Analysis', icon: Shield },
    { id: 'monitor', label: 'System Monitor', icon: Monitor },
    { id: 'history', label: 'Scan History', icon: ExternalLink },
    { id: 'stats', label: 'Security Statistics', icon: BarChart3 }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
      {/* Header */}
      <header className="bg-white shadow-lg border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="bg-gradient-to-r from-blue-600 to-indigo-600 p-3 rounded-xl shadow-lg">
                <Shield className="text-white" size={28} />
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                  PhishTrap Real-Time {isElectron && <span className="text-sm text-gray-500">Desktop v{appVersion}</span>}
                </h1>
                <p className="text-sm text-gray-600">
                  Real-Time Website Security Analysis • Live Threat Detection • {isElectron ? 'Desktop Application' : 'Web Application'}
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              {/* Export Button */}
              <button
                onClick={handleExportResults}
                className="flex items-center space-x-2 px-3 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
                title="Export Results"
              >
                <Download size={16} />
                <span className="text-sm font-medium text-gray-700">Export</span>
              </button>
              
              {/* System Status Indicator */}
              <div className="flex items-center space-x-2 px-3 py-2 bg-gray-100 rounded-lg">
                <div className={`w-2 h-2 rounded-full ${systemStatus.isActive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
                <span className="text-sm font-medium text-gray-700">
                  {systemStatus.isActive ? 'ACTIVE' : 'INACTIVE'}
                </span>
                <span className="text-xs text-gray-500">
                  ({systemStatus.protectionLevel})
                </span>
              </div>
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-600 hover:text-blue-600 transition-colors"
              >
                <Github size={20} />
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex space-x-8">
            {tabs.map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center space-x-2 py-4 px-2 border-b-2 font-medium text-sm transition-colors ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  <Icon size={16} />
                  <span>{tab.label}</span>
                  {tab.id === 'monitor' && systemStatus.isActive && (
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {activeTab === 'analyze' && (
          <div className="max-w-5xl mx-auto">
            <RealTimeURLInput 
              onAnalyze={handleAnalyze} 
              isLoading={isLoading}
              systemStatus={systemStatus}
              onToggleSystem={handleToggleSystem}
              onChangeProtectionLevel={handleChangeProtectionLevel}
            />
            
            {isLoading && (
              <div className="bg-white rounded-xl shadow-lg p-8 text-center">
                <div className="flex items-center justify-center space-x-4 mb-4">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                  <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-indigo-600" style={{ animationDelay: '0.1s' }}></div>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-purple-600" style={{ animationDelay: '0.2s' }}></div>
                </div>
                <p className="text-gray-600 mb-2">Performing real-time security analysis...</p>
                <div className="text-sm text-gray-500 space-y-1">
                  <p>• Analyzing URL structure and patterns</p>
                  <p>• Checking SSL certificates and security headers</p>
                  <p>• Scanning for XSS and SQL injection attempts</p>
                  <p>• Detecting phishing and malware indicators</p>
                  <p>• Performing real-time threat assessment</p>
                </div>
              </div>
            )}
            
            {currentResult && !isLoading && (
              <RealTimeAnalysisResults result={currentResult} />
            )}
          </div>
        )}

        {activeTab === 'monitor' && (
          <div className="max-w-4xl mx-auto">
            <SystemStatusMonitor 
              systemStatus={systemStatus}
              onToggleSystem={handleToggleSystem}
            />
          </div>
        )}

        {activeTab === 'history' && (
          <div className="max-w-4xl mx-auto">
            <ScanHistory 
              history={scanHistory}
              onClearHistory={handleClearHistory}
              onSelectScan={handleSelectScan}
            />
          </div>
        )}

        {activeTab === 'stats' && (
          <div className="max-w-5xl mx-auto">
            <AdvancedStatistics history={scanHistory} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-12">
        <div className="max-w-7xl mx-auto px-4 py-8">
          <div className="text-center">
            <div className="flex items-center justify-center space-x-6 mb-4">
              <div className="flex items-center space-x-2 text-sm text-gray-600">
                <Shield className="text-green-500" size={16} />
                <span>Real-Time Analysis</span>
              </div>
              <div className="flex items-center space-x-2 text-sm text-gray-600">
                <Bug className="text-red-500" size={16} />
                <span>Vulnerability Detection</span>
              </div>
              <div className="flex items-center space-x-2 text-sm text-gray-600">
                <Activity className="text-purple-500" size={16} />
                <span>Live Monitoring</span>
              </div>
              <div className="flex items-center space-x-2 text-sm text-gray-600">
                <ExternalLink className="text-blue-500" size={16} />
                <span>Actual Results</span>
              </div>
            </div>
            <p className="text-gray-600 text-sm mb-2">
              PhishTrap Real-Time provides genuine website security analysis with actual threat detection.
            </p>
            <p className="text-gray-500 text-xs">
              Real-time security analysis tool • Educational and demonstration purposes • Always verify results independently
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;