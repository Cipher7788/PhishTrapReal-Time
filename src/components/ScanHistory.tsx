import React from 'react';
import { Clock, Shield, AlertTriangle, X, Trash2 } from 'lucide-react';
import { ScanHistory as ScanHistoryType } from '../types';

interface ScanHistoryProps {
  history: ScanHistoryType[];
  onClearHistory: () => void;
  onSelectScan: (url: string) => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({ 
  history, 
  onClearHistory, 
  onSelectScan 
}) => {
  if (history.length === 0) {
    return (
      <div className="bg-white rounded-xl shadow-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-800">Recent Scans</h3>
        </div>
        <div className="text-center py-8">
          <Clock className="mx-auto text-gray-400 mb-2" size={48} />
          <p className="text-gray-500">No scans yet. Analyze a URL to get started!</p>
        </div>
      </div>
    );
  }

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'safe':
        return <Shield className="text-green-500" size={16} />;
      case 'suspicious':
        return <AlertTriangle className="text-amber-500" size={16} />;
      case 'malicious':
        return <X className="text-red-500" size={16} />;
    }
  };

  const getThreatBadge = (level: string) => {
    switch (level) {
      case 'safe':
        return 'bg-green-100 text-green-800';
      case 'suspicious':
        return 'bg-amber-100 text-amber-800';
      case 'malicious':
        return 'bg-red-100 text-red-800';
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-800">Recent Scans</h3>
        <button
          onClick={onClearHistory}
          className="flex items-center space-x-2 text-red-600 hover:text-red-700 transition-colors"
        >
          <Trash2 size={16} />
          <span>Clear</span>
        </button>
      </div>

      <div className="space-y-3 max-h-96 overflow-y-auto">
        {history.map((scan) => (
          <div
            key={scan.id}
            className="p-4 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer transition-colors"
            onClick={() => onSelectScan(scan.url)}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center space-x-2">
                {getThreatIcon(scan.threatLevel)}
                <span className={`text-xs px-2 py-1 rounded-full ${getThreatBadge(scan.threatLevel)}`}>
                  {scan.threatLevel.toUpperCase()}
                </span>
              </div>
              <span className="text-xs text-gray-500">
                {new Date(scan.timestamp).toLocaleString()}
              </span>
            </div>
            
            <p className="text-sm text-gray-700 truncate mb-1">{scan.url}</p>
            <p className="text-xs text-gray-500">Risk Score: {scan.score}</p>
          </div>
        ))}
      </div>
    </div>
  );
};