import React from 'react';
import { BarChart3, Shield, AlertTriangle, X, TrendingUp, Bug, Zap, Activity, Eye, Globe } from 'lucide-react';
import { ScanHistory } from '../types';

interface AdvancedStatisticsProps {
  history: ScanHistory[];
}

export const AdvancedStatistics: React.FC<AdvancedStatisticsProps> = ({ history }) => {
  const totalScans = history.length;
  const safeScans = history.filter(scan => scan.threatLevel === 'safe').length;
  const suspiciousScans = history.filter(scan => scan.threatLevel === 'suspicious').length;
  const maliciousScans = history.filter(scan => scan.threatLevel === 'malicious').length;
  const criticalScans = history.filter(scan => scan.threatLevel === 'critical').length;

  const totalVulnerabilities = history.reduce((sum, scan) => sum + scan.vulnerabilities, 0);
  const totalRealTimeThreats = history.reduce((sum, scan) => sum + scan.realTimeThreats, 0);

  const averageScore = totalScans > 0 
    ? Math.round(history.reduce((sum, scan) => sum + scan.score, 0) / totalScans)
    : 0;

  const averageVulnerabilities = totalScans > 0
    ? Math.round(totalVulnerabilities / totalScans * 10) / 10
    : 0;

  const threatDistribution = [
    { label: 'Safe', value: safeScans, color: 'green', icon: Shield },
    { label: 'Suspicious', value: suspiciousScans, color: 'amber', icon: AlertTriangle },
    { label: 'Malicious', value: maliciousScans, color: 'red', icon: X },
    { label: 'Critical', value: criticalScans, color: 'red', icon: Bug }
  ];

  const securityMetrics = [
    {
      label: 'Total Vulnerabilities',
      value: totalVulnerabilities,
      icon: <Bug className="text-red-500" size={24} />,
      color: 'red'
    },
    {
      label: 'Real-time Threats',
      value: totalRealTimeThreats,
      icon: <Zap className="text-orange-500" size={24} />,
      color: 'orange'
    },
    {
      label: 'Average Risk Score',
      value: averageScore,
      icon: <TrendingUp className="text-blue-500" size={24} />,
      color: 'blue'
    },
    {
      label: 'Avg Vulnerabilities',
      value: averageVulnerabilities,
      icon: <Activity className="text-purple-500" size={24} />,
      color: 'purple'
    }
  ];

  if (totalScans === 0) {
    return (
      <div className="bg-white rounded-xl shadow-lg p-6">
        <div className="flex items-center space-x-3 mb-4">
          <TrendingUp className="text-blue-500" size={24} />
          <h3 className="text-lg font-semibold text-gray-800">Advanced Security Statistics</h3>
        </div>
        <div className="text-center py-8">
          <BarChart3 className="mx-auto text-gray-400 mb-2" size={48} />
          <p className="text-gray-500">Statistics will appear after you analyze some URLs</p>
        </div>
      </div>
    );
  }

  const safetyRate = Math.round((safeScans / totalScans) * 100);
  const threatRate = Math.round(((suspiciousScans + maliciousScans + criticalScans) / totalScans) * 100);

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="bg-white rounded-xl shadow-lg p-6">
        <div className="flex items-center space-x-3 mb-6">
          <TrendingUp className="text-blue-500" size={24} />
          <h3 className="text-lg font-semibold text-gray-800">Security Overview</h3>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          {securityMetrics.map((metric, index) => (
            <div key={index} className="bg-gray-50 rounded-lg p-4">
              <div className="flex items-center space-x-3">
                {metric.icon}
                <div>
                  <p className="text-2xl font-bold text-gray-800">{metric.value}</p>
                  <p className="text-sm text-gray-600">{metric.label}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Safety Rate Indicator */}
        <div className="bg-gray-50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700">Overall Safety Rate</span>
            <span className="text-lg font-bold text-gray-800">{safetyRate}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-3">
            <div
              className={`h-3 rounded-full transition-all duration-500 ${
                safetyRate >= 70 ? 'bg-green-500' : 
                safetyRate >= 40 ? 'bg-yellow-500' : 
                'bg-red-500'
              }`}
              style={{ width: `${safetyRate}%` }}
            />
          </div>
          <div className="flex justify-between text-xs text-gray-500 mt-1">
            <span>High Risk</span>
            <span>Low Risk</span>
          </div>
        </div>
      </div>

      {/* Threat Distribution */}
      <div className="bg-white rounded-xl shadow-lg p-6">
        <h4 className="text-lg font-semibold text-gray-800 mb-4">Threat Level Distribution</h4>
        
        <div className="space-y-4">
          {threatDistribution.map((threat, index) => {
            const Icon = threat.icon;
            const percentage = totalScans > 0 ? Math.round((threat.value / totalScans) * 100) : 0;
            
            return (
              <div key={index} className="flex items-center space-x-4">
                <div className="flex items-center space-x-2 w-24">
                  <Icon className={`text-${threat.color}-500`} size={16} />
                  <span className="text-sm font-medium text-gray-700">{threat.label}</span>
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <div className="w-full bg-gray-200 rounded-full h-2 mr-3">
                      <div
                        className={`h-2 rounded-full bg-${threat.color}-500 transition-all duration-500`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                    <span className="text-sm text-gray-600 w-16 text-right">
                      {threat.value} ({percentage}%)
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Trends */}
      <div className="bg-white rounded-xl shadow-lg p-6">
        <h4 className="text-lg font-semibold text-gray-800 mb-4">Security Insights</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Risk Assessment */}
          <div className="space-y-3">
            <h5 className="font-medium text-gray-700">Risk Assessment</h5>
            <div className="space-y-2">
              <div className="flex items-center justify-between p-2 bg-gray-50 rounded">
                <span className="text-sm text-gray-600">High-Risk URLs</span>
                <span className="font-semibold text-red-600">{maliciousScans + criticalScans}</span>
              </div>
              <div className="flex items-center justify-between p-2 bg-gray-50 rounded">
                <span className="text-sm text-gray-600">Medium-Risk URLs</span>
                <span className="font-semibold text-yellow-600">{suspiciousScans}</span>
              </div>
              <div className="flex items-center justify-between p-2 bg-gray-50 rounded">
                <span className="text-sm text-gray-600">Low-Risk URLs</span>
                <span className="font-semibold text-green-600">{safeScans}</span>
              </div>
            </div>
          </div>

          {/* Vulnerability Breakdown */}
          <div className="space-y-3">
            <h5 className="font-medium text-gray-700">Security Metrics</h5>
            <div className="space-y-2">
              <div className="flex items-center justify-between p-2 bg-gray-50 rounded">
                <span className="text-sm text-gray-600">Total Scans</span>
                <span className="font-semibold text-blue-600">{totalScans}</span>
              </div>
              <div className="flex items-center justify-between p-2 bg-gray-50 rounded">
                <span className="text-sm text-gray-600">Vulnerabilities Found</span>
                <span className="font-semibold text-red-600">{totalVulnerabilities}</span>
              </div>
              <div className="flex items-center justify-between p-2 bg-gray-50 rounded">
                <span className="text-sm text-gray-600">Real-time Threats</span>
                <span className="font-semibold text-orange-600">{totalRealTimeThreats}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Security Recommendations */}
        <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <h5 className="font-medium text-blue-800 mb-2">Security Recommendations</h5>
          <div className="space-y-1 text-sm text-blue-700">
            {threatRate > 50 && (
              <p>• High threat detection rate - consider enabling additional security measures</p>
            )}
            {totalVulnerabilities > 10 && (
              <p>• Multiple vulnerabilities detected - review security practices</p>
            )}
            {averageScore > 50 && (
              <p>• High average risk score - be more cautious with URL sources</p>
            )}
            {safetyRate > 80 && (
              <p>• Good security awareness - continue following best practices</p>
            )}
            <p>• Always verify URLs from unknown sources before visiting</p>
            <p>• Keep your browser and security software updated</p>
          </div>
        </div>
      </div>
    </div>
  );
};