import React from 'react';
import { Shield, AlertTriangle, X, CheckCircle, XCircle, Info } from 'lucide-react';
import { AnalysisResult } from '../types';

interface AnalysisResultsProps {
  result: AnalysisResult;
}

export const AnalysisResults: React.FC<AnalysisResultsProps> = ({ result }) => {
  const getThreatIcon = () => {
    switch (result.threatLevel) {
      case 'safe':
        return <Shield className="text-green-500" size={24} />;
      case 'suspicious':
        return <AlertTriangle className="text-amber-500" size={24} />;
      case 'malicious':
        return <X className="text-red-500" size={24} />;
    }
  };

  const getThreatColor = () => {
    switch (result.threatLevel) {
      case 'safe':
        return 'green';
      case 'suspicious':
        return 'amber';
      case 'malicious':
        return 'red';
    }
  };

  const getThreatBgColor = () => {
    switch (result.threatLevel) {
      case 'safe':
        return 'bg-green-50 border-green-200';
      case 'suspicious':
        return 'bg-amber-50 border-amber-200';
      case 'malicious':
        return 'bg-red-50 border-red-200';
    }
  };

  const color = getThreatColor();
  const bgColor = getThreatBgColor();

  return (
    <div className="space-y-6">
      {/* Overall Result */}
      <div className={`rounded-xl border-2 ${bgColor} p-6`}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            {getThreatIcon()}
            <div>
              <h3 className="text-xl font-semibold text-gray-800">
                {result.threatLevel.charAt(0).toUpperCase() + result.threatLevel.slice(1)}
              </h3>
              <p className="text-sm text-gray-600">
                Risk Score: {result.score}/{result.maxScore}
              </p>
            </div>
          </div>
          <div className={`text-${color}-600 font-mono text-sm`}>
            {new Date(result.timestamp).toLocaleTimeString()}
          </div>
        </div>

        <div className="mb-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700">Risk Level</span>
            <span className="text-sm text-gray-600">
              {Math.round((result.score / result.maxScore) * 100)}%
            </span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div
              className={`h-2 rounded-full bg-${color}-500 transition-all duration-500`}
              style={{ width: `${(result.score / result.maxScore) * 100}%` }}
            />
          </div>
        </div>

        <div className="mb-4">
          <p className="text-sm text-gray-600 mb-2">
            <span className="font-medium">Analyzed URL:</span>
          </p>
          <p className="break-all bg-gray-100 p-3 rounded-lg font-mono text-sm">
            {result.url}
          </p>
        </div>
      </div>

      {/* Security Checks */}
      <div className="bg-white rounded-xl shadow-lg p-6">
        <h3 className="text-lg font-semibold text-gray-800 mb-4">
          Security Analysis
        </h3>
        
        <div className="space-y-3">
          {result.checks.map((check, index) => (
            <div
              key={index}
              className={`p-4 rounded-lg border ${
                check.passed ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
              }`}
            >
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 mt-0.5">
                  {check.passed ? (
                    <CheckCircle className="text-green-500" size={20} />
                  ) : (
                    <XCircle className="text-red-500" size={20} />
                  )}
                </div>
                
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <h4 className="font-medium text-gray-800">{check.name}</h4>
                    {check.weight > 0 && (
                      <span className={`text-xs px-2 py-1 rounded-full ${
                        check.passed ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                      }`}>
                        {check.passed ? 'PASS' : `FAIL (-${check.weight})`}
                      </span>
                    )}
                  </div>
                  
                  <p className="text-sm text-gray-600 mb-2">{check.description}</p>
                  
                  {check.details && (
                    <div className="flex items-start space-x-2">
                      <Info size={14} className="text-gray-400 mt-0.5 flex-shrink-0" />
                      <p className="text-xs text-gray-500">{check.details}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Recommendations */}
      <div className="bg-white rounded-xl shadow-lg p-6">
        <h3 className="text-lg font-semibold text-gray-800 mb-4">
          Recommendations
        </h3>
        
        <div className="space-y-3">
          {result.recommendations.map((recommendation, index) => (
            <div
              key={index}
              className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg"
            >
              <div className="flex-shrink-0 mt-0.5">
                <Info className="text-blue-500" size={16} />
              </div>
              <p className="text-sm text-gray-700">{recommendation}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};