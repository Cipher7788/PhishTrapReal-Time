import React, { useState, useEffect } from 'react';
import { Activity, Shield, Zap, Eye, Globe, AlertTriangle, CheckCircle, X, TrendingUp } from 'lucide-react';
import { SystemStatus, RealTimeThreat } from '../types';

interface SystemStatusMonitorProps {
  systemStatus: SystemStatus;
  onToggleSystem: () => void;
}

export const SystemStatusMonitor: React.FC<SystemStatusMonitorProps> = ({ 
  systemStatus, 
  onToggleSystem 
}) => {
  const [recentActivity, setRecentActivity] = useState<string[]>([]);
  const [liveThreats, setLiveThreats] = useState<RealTimeThreat[]>([]);

  // Simulate real-time activity monitoring
  useEffect(() => {
    if (!systemStatus.isActive) {
      setRecentActivity([]);
      setLiveThreats([]);
      return;
    }

    const interval = setInterval(() => {
      const activities = [
        'Scanning incoming web requests...',
        'Analyzing URL patterns...',
        'Checking SSL certificates...',
        'Monitoring for XSS attempts...',
        'Detecting SQL injection patterns...',
        'Validating security headers...',
        'Analyzing content for threats...',
        'Checking domain reputation...'
      ];

      const newActivity = activities[Math.floor(Math.random() * activities.length)];
      setRecentActivity(prev => [
        `${new Date().toLocaleTimeString()}: ${newActivity}`,
        ...prev.slice(0, 4)
      ]);

      // Simulate threat detection
      if (Math.random() < 0.2) { // 20% chance of detecting a threat
        const threatTypes = ['phishing', 'malware', 'tracking', 'suspicious_redirect', 'data_harvesting'];
        const severities = ['low', 'medium', 'high', 'critical'];
        
        const newThreat: RealTimeThreat = {
          type: threatTypes[Math.floor(Math.random() * threatTypes.length)] as any,
          severity: severities[Math.floor(Math.random() * severities.length)] as any,
          description: `Real-time ${threatTypes[Math.floor(Math.random() * threatTypes.length)]} attempt blocked`,
          timestamp: Date.now(),
          blocked: Math.random() > 0.2, // 80% chance of blocking
          evidence: 'Detected by real-time monitoring system',
          source: 'Live Monitor'
        };

        setLiveThreats(prev => [newThreat, ...prev.slice(0, 9)]); // Keep last 10 threats
      }
    }, 2000); // Update every 2 seconds

    return () => clearInterval(interval);
  }, [systemStatus.isActive]);

  const getThreatIcon = (type: string) => {
    switch (type) {
      case 'malware': return <AlertTriangle className="text-red-500" size={14} />;
      case 'phishing': return <Shield className="text-orange-500" size={14} />;
      case 'tracking': return <Eye className="text-blue-500" size={14} />;
      case 'suspicious_redirect': return <Globe className="text-purple-500" size={14} />;
      case 'data_harvesting': return <Activity className="text-red-500" size={14} />;
      default: return <AlertTriangle className="text-gray-500" size={14} />;
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

  const getProtectionLevelColor = (level: string) => {
    switch (level) {
      case 'basic': return 'text-blue-600 bg-blue-100';
      case 'enhanced': return 'text-orange-600 bg-orange-100';
      case 'maximum': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-lg p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className={`p-2 rounded-lg ${systemStatus.isActive ? 'bg-green-100' : 'bg-gray-100'}`}>
            <Activity className={`${systemStatus.isActive ? 'text-green-600' : 'text-gray-400'}`} size={24} />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-800">System Status Monitor</h3>
            <p className="text-sm text-gray-600">Real-time security monitoring and threat detection</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-3">
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${getProtectionLevelColor(systemStatus.protectionLevel)}`}>
            {systemStatus.protectionLevel.toUpperCase()}
          </span>
          <div className={`w-3 h-3 rounded-full ${
            systemStatus.isActive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'
          }`} />
        </div>
      </div>

      {/* System Metrics */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-blue-50 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-blue-600">{systemStatus.sitesAnalyzed}</div>
          <div className="text-sm text-gray-600">Sites Analyzed</div>
          <div className="text-xs text-gray-500 mt-1">
            {systemStatus.isActive ? '+1 every analysis' : 'System inactive'}
          </div>
        </div>
        <div className="bg-red-50 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-red-600">{systemStatus.threatsBlocked}</div>
          <div className="text-sm text-gray-600">Threats Blocked</div>
          <div className="text-xs text-gray-500 mt-1">
            {systemStatus.isActive ? 'Real-time protection' : 'Protection disabled'}
          </div>
        </div>
        <div className="bg-green-50 rounded-lg p-4 text-center">
          <div className={`text-2xl font-bold ${systemStatus.isActive ? 'text-green-600' : 'text-gray-400'}`}>
            {systemStatus.isActive ? 'ONLINE' : 'OFFLINE'}
          </div>
          <div className="text-sm text-gray-600">System Status</div>
          <div className="text-xs text-gray-500 mt-1">
            Last activity: {new Date(systemStatus.lastActivity).toLocaleTimeString()}
          </div>
        </div>
      </div>

      {/* Real-time Activity Feed */}
      <div className="mb-6">
        <h4 className="font-semibold text-gray-800 mb-3 flex items-center space-x-2">
          <TrendingUp size={16} />
          <span>Real-time Activity</span>
        </h4>
        
        {!systemStatus.isActive ? (
          <div className="text-center py-6 bg-gray-50 rounded-lg">
            <Activity className="mx-auto text-gray-400 mb-2" size={32} />
            <p className="text-gray-500 text-sm">System is inactive - no monitoring in progress</p>
          </div>
        ) : recentActivity.length === 0 ? (
          <div className="text-center py-6 bg-blue-50 rounded-lg">
            <Activity className="mx-auto text-blue-500 mb-2 animate-spin" size={32} />
            <p className="text-blue-600 text-sm">Initializing real-time monitoring...</p>
          </div>
        ) : (
          <div className="bg-gray-50 rounded-lg p-4 max-h-32 overflow-y-auto">
            <div className="space-y-1">
              {recentActivity.map((activity, index) => (
                <div key={index} className="text-xs text-gray-600 font-mono">
                  {activity}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Live Threat Detection */}
      <div className="mb-6">
        <h4 className="font-semibold text-gray-800 mb-3 flex items-center space-x-2">
          <Shield size={16} />
          <span>Live Threat Detection</span>
        </h4>
        
        {liveThreats.length === 0 ? (
          <div className="text-center py-4 bg-green-50 rounded-lg">
            <CheckCircle className="mx-auto text-green-500 mb-2" size={24} />
            <p className="text-green-600 text-sm">No threats detected</p>
          </div>
        ) : (
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {liveThreats.slice(0, 5).map((threat, index) => (
              <div
                key={index}
                className={`p-3 rounded-lg border text-sm ${
                  threat.severity === 'critical' ? 'bg-red-50 border-red-200' :
                  threat.severity === 'high' ? 'bg-orange-50 border-orange-200' :
                  threat.severity === 'medium' ? 'bg-yellow-50 border-yellow-200' :
                  'bg-blue-50 border-blue-200'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center space-x-2">
                    {getThreatIcon(threat.type)}
                    <span className="font-medium text-gray-800">
                      {threat.type.replace('_', ' ').toUpperCase()}
                    </span>
                    <span className={`text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                      {threat.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center space-x-1">
                    {threat.blocked ? (
                      <CheckCircle className="text-green-500" size={12} />
                    ) : (
                      <X className="text-red-500" size={12} />
                    )}
                    <span className={`text-xs px-1 py-0.5 rounded ${
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

      {/* Protection Features Status */}
      <div className="border-t border-gray-200 pt-4">
        <h4 className="font-semibold text-gray-800 mb-3">Active Protection Features</h4>
        <div className="grid grid-cols-2 gap-2 text-sm">
          {[
            { name: 'XSS Protection', active: systemStatus.isActive },
            { name: 'SQL Injection Detection', active: systemStatus.isActive },
            { name: 'Phishing Detection', active: systemStatus.isActive },
            { name: 'Malware Scanning', active: systemStatus.isActive && systemStatus.protectionLevel !== 'basic' },
            { name: 'Real-time Monitoring', active: systemStatus.isActive && systemStatus.protectionLevel === 'maximum' },
            { name: 'Advanced Threat Analysis', active: systemStatus.isActive && systemStatus.protectionLevel === 'maximum' }
          ].map((feature, index) => (
            <div key={index} className="flex items-center space-x-2">
              {feature.active ? (
                <CheckCircle className="text-green-500" size={14} />
              ) : (
                <X className="text-gray-400" size={14} />
              )}
              <span className={feature.active ? 'text-gray-700' : 'text-gray-400'}>
                {feature.name}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};