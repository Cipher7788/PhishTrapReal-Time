import React, { useState } from 'react';
import { Search, Clipboard, X, Shield, Zap, Activity, Settings } from 'lucide-react';

interface AdvancedURLInputProps {
  onAnalyze: (url: string, enableCrawler: boolean, enableRealTime: boolean) => void;
  isLoading: boolean;
  webActivityMonitor: { isActive: boolean; threatsBlocked: number; requestsAnalyzed: number };
}

export const AdvancedURLInput: React.FC<AdvancedURLInputProps> = ({ 
  onAnalyze, 
  isLoading, 
  webActivityMonitor 
}) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [enableCrawler, setEnableCrawler] = useState(true);
  const [enableRealTime, setEnableRealTime] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) {
      setError('Please enter a URL to analyze');
      return;
    }
    setError('');
    onAnalyze(url.trim(), enableCrawler, enableRealTime);
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
      label: 'Safe URL',
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
      url: 'https://example.com/login?user=admin\' OR 1=1--',
      type: 'sql'
    },
    {
      label: 'OTP Bypass',
      url: 'https://fake-bank.com/otp-bypass-tool',
      type: 'otp'
    },
    {
      label: 'Phishing Site',
      url: 'https://secure-login.google-verify.tk/account/suspended',
      type: 'phishing'
    },
    {
      label: 'Malware Distribution',
      url: 'http://192.168.1.1/malware-download.exe',
      type: 'malware'
    }
  ];

  return (
    <div className="bg-white rounded-xl shadow-lg p-6 mb-8">
      {/* Web Activity Monitor Status */}
      <div className="mb-6 p-4 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg border border-blue-200">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <Activity className={`${webActivityMonitor.isActive ? 'text-green-500' : 'text-gray-400'}`} size={20} />
            <span className="font-semibold text-gray-800">Real-Time Protection</span>
            <div className={`w-2 h-2 rounded-full ${webActivityMonitor.isActive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
          </div>
          <span className={`text-sm px-2 py-1 rounded-full ${webActivityMonitor.isActive ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'}`}>
            {webActivityMonitor.isActive ? 'ACTIVE' : 'INACTIVE'}
          </span>
        </div>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="flex items-center space-x-2">
            <Shield className="text-blue-500" size={16} />
            <span className="text-gray-600">Threats Blocked:</span>
            <span className="font-bold text-red-600">{webActivityMonitor.threatsBlocked}</span>
          </div>
          <div className="flex items-center space-x-2">
            <Zap className="text-yellow-500" size={16} />
            <span className="text-gray-600">Requests Analyzed:</span>
            <span className="font-bold text-blue-600">{webActivityMonitor.requestsAnalyzed}</span>
          </div>
        </div>
      </div>

      <h2 className="text-xl font-semibold text-gray-800 mb-4">
        Advanced Security Analysis
      </h2>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="relative">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com or paste suspicious URL"
            className={`w-full px-4 py-3 pr-20 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              error ? 'border-red-500' : 'border-gray-300'
            }`}
            disabled={isLoading}
          />
          
          <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex space-x-1">
            {url && (
              <button
                type="button"
                onClick={clearInput}
                className="p-1 text-gray-400 hover:text-red-500 transition-colors"
                disabled={isLoading}
              >
                <X size={16} />
              </button>
            )}
            
            <button
              type="button"
              onClick={handlePaste}
              className="p-1 text-gray-400 hover:text-blue-500 transition-colors"
              disabled={isLoading}
              title="Paste from clipboard"
            >
              <Clipboard size={16} />
            </button>
          </div>
        </div>

        {error && (
          <p className="text-red-500 text-sm">{error}</p>
        )}

        {/* Advanced Options */}
        <div className="border border-gray-200 rounded-lg p-4">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center space-x-2 text-gray-700 hover:text-blue-600 transition-colors"
          >
            <Settings size={16} />
            <span>Advanced Options</span>
            <span className={`transform transition-transform ${showAdvanced ? 'rotate-180' : ''}`}>▼</span>
          </button>
          
          {showAdvanced && (
            <div className="mt-4 space-y-3">
              <label className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  checked={enableCrawler}
                  onChange={(e) => setEnableCrawler(e.target.checked)}
                  className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
                <div>
                  <span className="text-sm font-medium text-gray-700">High-Intensity Web Crawler</span>
                  <p className="text-xs text-gray-500">Deep analysis of page content, forms, and scripts</p>
                </div>
              </label>
              
              <label className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  checked={enableRealTime}
                  onChange={(e) => setEnableRealTime(e.target.checked)}
                  className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
                <div>
                  <span className="text-sm font-medium text-gray-700">Real-Time Threat Monitoring</span>
                  <p className="text-xs text-gray-500">Live detection of malware, phishing, and tracking</p>
                </div>
              </label>
            </div>
          )}
        </div>

        <div className="flex space-x-3">
          <button
            type="submit"
            disabled={isLoading || !url.trim()}
            className="flex-1 bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-3 px-6 rounded-lg hover:from-blue-700 hover:to-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2"
          >
            <Search size={20} />
            <span>{isLoading ? 'Analyzing...' : 'Deep Security Scan'}</span>
          </button>
        </div>
      </form>

      {/* Test URLs */}
      <div className="mt-6 text-sm text-gray-600">
        <p className="mb-3 font-medium">Test URLs for Different Attack Vectors:</p>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          {testUrls.map((test, index) => (
            <button
              key={index}
              onClick={() => setUrl(test.url)}
              className={`px-3 py-2 rounded-lg text-left transition-colors ${
                test.type === 'safe' ? 'bg-green-100 hover:bg-green-200 text-green-800' :
                test.type === 'xss' ? 'bg-orange-100 hover:bg-orange-200 text-orange-800' :
                test.type === 'sql' ? 'bg-purple-100 hover:bg-purple-200 text-purple-800' :
                test.type === 'otp' ? 'bg-yellow-100 hover:bg-yellow-200 text-yellow-800' :
                test.type === 'phishing' ? 'bg-red-100 hover:bg-red-200 text-red-800' :
                'bg-gray-100 hover:bg-gray-200 text-gray-800'
              }`}
            >
              <div className="font-medium">{test.label}</div>
              <div className="text-xs opacity-75 truncate">{test.url.substring(0, 30)}...</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};