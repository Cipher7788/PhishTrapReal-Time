import React, { useState } from 'react';
import { Search, Clipboard, X, Shield, Activity, Power, Settings } from 'lucide-react';
import { SystemStatus } from '../types';

interface RealTimeURLInputProps {
  onAnalyze: (url: string) => void;
  isLoading: boolean;
  systemStatus: SystemStatus;
  onToggleSystem: () => void;
  onChangeProtectionLevel: (level: 'basic' | 'enhanced' | 'maximum') => void;
}

export const RealTimeURLInput: React.FC<RealTimeURLInputProps> = ({ 
  onAnalyze, 
  isLoading, 
  systemStatus,
  onToggleSystem,
  onChangeProtectionLevel
}) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [showSettings, setShowSettings] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) {
      setError('Please enter a URL to analyze');
      return;
    }
    if (!systemStatus.isActive) {
      setError('Please activate the security system first');
      return;
    }
    setError('');
    onAnalyze(url.trim());
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setUrl(text);
      setError('');
    } catch (err) {
      setError('Unable to access clipboard');
    }
  };

  const clearInput = () => {
    setUrl('');
    setError('');
  };

  const testUrls = [
    {
      label: 'Safe Website',
      url: 'https://google.com',
      type: 'safe'
    },
    {
      label: 'XSS Test',
      url: 'https://example.com/search?q=<script>alert("xss")</script>',
      type: 'xss'
    },
    {
      label: 'SQL Injection',
      url: 'https://vulnerable-site.com/login?user=admin\' OR 1=1--',
      type: 'sql'
    },
    {
      label: 'Phishing Simulation',
      url: 'https://secure-login.verify-account.tk/suspended',
      type: 'phishing'
    },
    {
      label: 'IP Address Site',
      url: 'http://192.168.1.1/admin',
      type: 'ip'
    },
    {
      label: 'Suspicious Redirect',
      url: 'https://bit.ly/suspicious-link',
      type: 'redirect'
    }
  ];

  return (
    <div className="bg-white rounded-xl shadow-lg p-6 mb-8">
      {/* System Status Header */}
      <div className="mb-6 p-4 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg border border-blue-200">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-lg ${systemStatus.isActive ? 'bg-green-100' : 'bg-gray-100'}`}>
              <Shield className={`${systemStatus.isActive ? 'text-green-600' : 'text-gray-400'}`} size={24} />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-gray-800">Real-Time Security System</h3>
              <p className="text-sm text-gray-600">
                Status: <span className={`font-medium ${systemStatus.isActive ? 'text-green-600' : 'text-red-600'}`}>
                  {systemStatus.isActive ? 'ACTIVE' : 'INACTIVE'}
                </span>
              </p>
            </div>
          </div>
          
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setShowSettings(!showSettings)}
              className="p-2 text-gray-600 hover:text-blue-600 transition-colors"
              title="Settings"
            >
              <Settings size={20} />
            </button>
            
            <button
              onClick={onToggleSystem}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-all ${
                systemStatus.isActive 
                  ? 'bg-red-100 text-red-700 hover:bg-red-200' 
                  : 'bg-green-100 text-green-700 hover:bg-green-200'
              }`}
            >
              <Power size={16} />
              <span>{systemStatus.isActive ? 'Deactivate' : 'Activate'}</span>
            </button>
          </div>
        </div>

        {/* System Statistics */}
        <div className="grid grid-cols-3 gap-4 text-sm">
          <div className="flex items-center space-x-2">
            <Activity className="text-blue-500" size={16} />
            <span className="text-gray-600">Sites Analyzed:</span>
            <span className="font-bold text-blue-600">{systemStatus.sitesAnalyzed}</span>
          </div>
          <div className="flex items-center space-x-2">
            <Shield className="text-red-500" size={16} />
            <span className="text-gray-600">Threats Blocked:</span>
            <span className="font-bold text-red-600">{systemStatus.threatsBlocked}</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className={`w-2 h-2 rounded-full ${systemStatus.isActive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
            <span className="text-gray-600">Protection:</span>
            <span className={`font-bold ${
              systemStatus.protectionLevel === 'maximum' ? 'text-red-600' :
              systemStatus.protectionLevel === 'enhanced' ? 'text-orange-600' :
              'text-blue-600'
            }`}>
              {systemStatus.protectionLevel.toUpperCase()}
            </span>
          </div>
        </div>

        {/* Settings Panel */}
        {showSettings && (
          <div className="mt-4 pt-4 border-t border-blue-200">
            <h4 className="font-medium text-gray-800 mb-3">Protection Level</h4>
            <div className="flex space-x-2">
              {(['basic', 'enhanced', 'maximum'] as const).map(level => (
                <button
                  key={level}
                  onClick={() => onChangeProtectionLevel(level)}
                  className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    systemStatus.protectionLevel === level
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  {level.charAt(0).toUpperCase() + level.slice(1)}
                </button>
              ))}
            </div>
            <div className="mt-2 text-xs text-gray-600">
              <p><strong>Basic:</strong> URL analysis only</p>
              <p><strong>Enhanced:</strong> + Content analysis and vulnerability detection</p>
              <p><strong>Maximum:</strong> + Real-time monitoring and advanced threat detection</p>
            </div>
          </div>
        )}
      </div>

      <h2 className="text-xl font-semibold text-gray-800 mb-4">
        Website Security Analysis
      </h2>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="relative">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com or paste any website URL"
            className={`w-full px-4 py-3 pr-20 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              error ? 'border-red-500' : 'border-gray-300'
            } ${!systemStatus.isActive ? 'bg-gray-50' : ''}`}
            disabled={isLoading || !systemStatus.isActive}
          />
          
          <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex space-x-1">
            {url && (
              <button
                type="button"
                onClick={clearInput}
                className="p-1 text-gray-400 hover:text-red-500 transition-colors"
                disabled={isLoading || !systemStatus.isActive}
              >
                <X size={16} />
              </button>
            )}
            
            <button
              type="button"
              onClick={handlePaste}
              className="p-1 text-gray-400 hover:text-blue-500 transition-colors"
              disabled={isLoading || !systemStatus.isActive}
              title="Paste from clipboard"
            >
              <Clipboard size={16} />
            </button>
          </div>
        </div>

        {error && (
          <p className="text-red-500 text-sm">{error}</p>
        )}

        <div className="flex space-x-3">
          <button
            type="submit"
            disabled={isLoading || !url.trim() || !systemStatus.isActive}
            className="flex-1 bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-3 px-6 rounded-lg hover:from-blue-700 hover:to-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2"
          >
            <Search size={20} />
            <span>{isLoading ? 'Analyzing...' : 'Analyze Website'}</span>
          </button>
        </div>
      </form>

      {/* Test URLs */}
      <div className="mt-6 text-sm text-gray-600">
        <p className="mb-3 font-medium">Test URLs (Real Analysis):</p>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          {testUrls.map((test, index) => (
            <button
              key={index}
              onClick={() => setUrl(test.url)}
              disabled={!systemStatus.isActive}
              className={`px-3 py-2 rounded-lg text-left transition-colors disabled:opacity-50 ${
                test.type === 'safe' ? 'bg-green-100 hover:bg-green-200 text-green-800' :
                test.type === 'xss' ? 'bg-orange-100 hover:bg-orange-200 text-orange-800' :
                test.type === 'sql' ? 'bg-purple-100 hover:bg-purple-200 text-purple-800' :
                test.type === 'phishing' ? 'bg-red-100 hover:bg-red-200 text-red-800' :
                test.type === 'ip' ? 'bg-yellow-100 hover:bg-yellow-200 text-yellow-800' :
                'bg-gray-100 hover:bg-gray-200 text-gray-800'
              }`}
            >
              <div className="font-medium">{test.label}</div>
              <div className="text-xs opacity-75 truncate">{test.url.substring(0, 30)}...</div>
            </button>
          ))}
        </div>
      </div>

      {!systemStatus.isActive && (
        <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
          <p className="text-yellow-800 text-sm">
            ⚠️ Security system is inactive. Click "Activate" to enable real-time website analysis.
          </p>
        </div>
      )}
    </div>
  );
};