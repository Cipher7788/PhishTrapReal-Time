import React from 'react';
import { BarChart3, Shield, AlertTriangle, X, TrendingUp } from 'lucide-react';
import { ScanHistory } from '../types';

interface StatisticsProps {
  history: ScanHistory[];
}

export const Statistics: React.FC<StatisticsProps> = ({ history }) => {
  const totalScans = history.length;
  const safeScans = history.filter(scan => scan.threatLevel === 'safe').length;
  const suspiciousScans = history.filter(scan => scan.threatLevel === 'suspicious').length;
  const maliciousScans = history.filter(scan => scan.threatLevel === 'malicious').length;

  const averageScore = totalScans > 0 
    ? Math.round(history.reduce((sum, scan) => sum + scan.score, 0) / totalScans)
    : 0;

  const stats = [
    {
      label: 'Total Scans',
      value: totalScans,
      icon: <BarChart3 className="text-blue-500" size={24} />,
      color: 'blue'
    },
    {
      label: 'Safe URLs',
      value: safeScans,
      icon: <Shield className="text-green-500" size={24} />,
      color: 'green'
    },
    {
      label: 'Suspicious URLs',
      value: suspiciousScans,
      icon: <AlertTriangle className="text-amber-500" size={24} />,
      color: 'amber'
    },
    {
      label: 'Malicious URLs',
      value: maliciousScans,
      icon: <X className="text-red-500" size={24} />,
      color: 'red'
    }
  ];

  if (totalScans === 0) {
    return (
      <div className="bg-white rounded-xl shadow-lg p-6">
        <div className="flex items-center space-x-3 mb-4">
          <TrendingUp className="text-blue-500" size={24} />
          <h3 className="text-lg font-semibold text-gray-800">Statistics</h3>
        </div>
        <div className="text-center py-8">
          <p className="text-gray-500">Statistics will appear after you analyze some URLs</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl shadow-lg p-6">
      <div className="flex items-center space-x-3 mb-6">
        <TrendingUp className="text-blue-500" size={24} />
        <h3 className="text-lg font-semibold text-gray-800">Statistics</h3>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-6">
        {stats.map((stat, index) => (
          <div key={index} className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center space-x-3">
              {stat.icon}
              <div>
                <p className="text-2xl font-bold text-gray-800">{stat.value}</p>
                <p className="text-sm text-gray-600">{stat.label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="bg-gray-50 rounded-lg p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-700">Average Risk Score</span>
          <span className="text-lg font-bold text-gray-800">{averageScore}</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div
            className={`h-2 rounded-full transition-all duration-500 ${
              averageScore >= 60 ? 'bg-red-500' : 
              averageScore >= 30 ? 'bg-amber-500' : 
              'bg-green-500'
            }`}
            style={{ width: `${averageScore}%` }}
          />
        </div>
      </div>

      {totalScans > 0 && (
        <div className="mt-4 text-center">
          <p className="text-sm text-gray-600">
            Safety Rate: {Math.round((safeScans / totalScans) * 100)}%
          </p>
        </div>
      )}
    </div>
  );
};