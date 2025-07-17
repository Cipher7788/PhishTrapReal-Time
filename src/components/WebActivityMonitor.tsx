import React, { useState, useEffect } from 'react';
import { Activity, Shield, Zap, Eye, Globe, AlertTriangle, CheckCircle, X } from 'lucide-react';
import { WebActivityMonitor as WebActivityMonitorType, RealTimeThreat } from '../types';

interface WebActivityMonitorProps {
  monitor: WebActivityMonitorType;
  onToggleMonitoring: () => void;
}

export const WebActivityMonitor: React.FC<WebActivityMonitorProps> = ({ 
  monitor, 
  onToggleMonitoring 
}) => {
  const [recentThreats, setRecentThreats] = useState<RealTimeThreat[]>([]);
  const [isExpanded, setIsExpanded] = useState(false);

  // Simulate real-time threat detection
  useEffect(() => {
    if (!monitor.isActive) return;

    const interval = setInterval(() => {
      // Simulate random threat detection
      if (Math.random() < 0.3) { // 30% chance of detecting a threat
        const threatTypes = ['tracking', 'malware', 'phishing', 'injection', 'redirect'];
        const severities = ['low', 'medium', 'high', 'critical'];
        const sources = ['Real-time scanner', 'Behavior analysis', 'Network monitor', 'Content filter'];
        
        const newThreat: RealTimeThreat = {
          type: threatTypes[Math.floor(Math.random() * threatTypes.length)] as any,
          severity: severities[Math.floor(Math.random() * severities.length)] as any,
          description: `Suspicious ${threatTypes[Math.floor(Math.random() * threatTypes.length)]} activity detected`,
          timestamp: Date.now(),
          blocked: Math.random() > 0.3, // 70% chance of blocking
          source: sources[Math.floor(Math.random() * sources.length)]
        };

        setRecentThreats(prev => [newThreat, ...prev.slice(0, 9)]); // Keep last 10 threats
      }
    }, 5000); // Check every 5 seconds

    return () => clearInterval(interval);
  }, [monitor.isActive]);

  const getThreatIcon = (type: string) => {
    switch (type) {
      case 'malware': return <AlertTriangle className="text-red-500" size={16} />;
      case 'phishing': return <Shield className="text-orange-500" size={16} />;
      case 'tracking': return <Eye className="text-blue-500" size={16} />;
      case 'injection': return <Zap className="text-purple-500" size={16} />;
      case 'redirect': return <Globe className="text-green-500" size={16} />;
      default: return <AlertTriangle className="text-gray-500" size={16} />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low': return 'text-blue-600';
      case 'medium': return 'text-yellow-600';
      case 'high': return 'text-orange-600';
      case 'critical': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          <Activity className={`${monitor.isActive ? 'text-green-500' : 'text-gray-400'}`} size={24} />
          <div>
            <h3 className="text-lg font-semibold text-gray-800">Web Activity Monitor</h3>
            <p className="text-sm text-gray-600">Real-time threat detection and blocking</p>
          </div>
        </div>
        <button
          onClick={onToggleMonitoring}
          className={`px-4 py-2 rounded-lg font-medium transition-colors ${
            monitor.isActive 
              ? 'bg-red-100 text-red-700 hover:bg-red-200' 
              : 'bg-green-100 text-green-700 hover:bg-green-200'
          }`}
        >
          {monitor.isActive ? 'Stop Monitoring' : 'Start Monitoring'}
        </button>
      </div>

      {/* Status Indicators */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-50 rounded-lg p-4 text-center">
          <div className={`text-2xl font-bold ${monitor.isActive ? 'text-green-600' : 'text-gray-400'}`}>
            {monitor.isActive ? 'ACTIVE' : 'INACTIVE'}
          </div>
          <div className="text-sm text-gray-600">Status</div>
          <div className={`w-3 h-3 rounded-full mx-auto mt-2 ${
            monitor.isActive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'
          }`} />
        </div>
        <div className="bg-red-50 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-red-600">{monitor.threatsBlocked}</div>
          <div className="text-sm text-gray-600">Threats Blocked</div>
        </div>
        <div className="bg-blue-50 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-blue-600">{monitor.requestsAnalyzed}</div>
          <div className="text-sm text-gray-600">Requests Analyzed</div>
        </div>
      </div>

      {/* Recent Threats */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h4 className="font-semibold text-gray-800">Recent Threats</h4>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="text-blue-600 hover:text-blue-700 text-sm"
          >
            {isExpanded ? 'Show Less' : 'Show More'}
          </button>
        </div>

        {recentThreats.length === 0 ? (
          <div className="text-center py-6">
            <CheckCircle className="mx-auto text-green-500 mb-2" size={32} />
            <p className="text-gray-500 text-sm">No threats detected recently</p>
          </div>
        ) : (
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {recentThreats.slice(0, isExpanded ? 10 : 3).map((threat, index) => (
              <div
                key={index}
                className={`p-3 rounded-lg border ${
                  threat.severity === 'critical' ? 'bg-red-50 border-red-200' :
                  threat.severity === 'high' ? 'bg-orange-50 border-orange-200' :
                  threat.severity === 'medium' ? 'bg-yellow-50 border-yellow-200' :
                  'bg-blue-50 border-blue-200'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center space-x-2">
                    {getThreatIcon(threat.type)}
                    <span className="font-medium text-gray-800 text-sm">
                      {threat.type.replace('_', ' ').toUpperCase()}
                    </span>
                    <span className={`text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                      {threat.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    {threat.blocked ? (
                      <CheckCircle className="text-green-500" size={14} />
                    ) : (
                      <X className="text-red-500" size={14} />
                    )}
                    <span className={`text-xs px-2 py-1 rounded-full ${
                      threat.blocked ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                    }`}>
                      {threat.blocked ? 'BLOCKED' : 'DETECTED'}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-gray-600 mb-1">{threat.description}</p>
                <div className="flex items-center justify-between text-xs text-gray-500">
                  <span>Source: {threat.source}</span>
                  <span>{new Date(threat.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Protection Features */}
      <div className="mt-6 pt-4 border-t border-gray-200">
        <h4 className="font-semibold text-gray-800 mb-3">Active Protection Features</h4>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="flex items-center space-x-2">
            <CheckCircle className="text-green-500" size={16} />
            <span className="text-gray-700">XSS Protection</span>
          </div>
          <div className="flex items-center space-x-2">
            <CheckCircle className="text-green-500" size={16} />
            <span className="text-gray-700">SQL Injection Detection</span>
          </div>
          <div className="flex items-center space-x-2">
            <CheckCircle className="text-green-500" size={16} />
            <span className="text-gray-700">Malware Scanning</span>
          </div>
          <div className="flex items-center space-x-2">
            <CheckCircle className="text-green-500" size={16} />
            <span className="text-gray-700">Phishing Detection</span>
          </div>
          <div className="flex items-center space-x-2">
            <CheckCircle className="text-green-500" size={16} />
            <span className="text-gray-700">OTP Bypass Prevention</span>
          </div>
          <div className="flex items-center space-x-2">
            <CheckCircle className="text-green-500" size={16} />
            <span className="text-gray-700">Real-time Blocking</span>
          </div>
        </div>
      </div>
    </div>
  );
};