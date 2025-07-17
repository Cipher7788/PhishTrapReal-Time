import React, { useState } from 'react';
import { Shield, AlertTriangle, X, CheckCircle, XCircle, Info, Bug, Zap, Activity, Eye, Globe, Code, Lock, Database } from 'lucide-react';
import { AnalysisResult, Vulnerability, RealTimeThreat, CrawlerResult } from '../types';

interface AdvancedAnalysisResultsProps {
  result: AnalysisResult;
}

export const AdvancedAnalysisResults: React.FC<AdvancedAnalysisResultsProps> = ({ result }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'vulnerabilities' | 'crawler' | 'realtime'>('overview');

  const getThreatIcon = () => {
    switch (result.threatLevel) {
      case 'safe':
        return <Shield className="text-green-500" size={24} />;
      case 'suspicious':
        return <AlertTriangle className="text-amber-500" size={24} />;
      case 'malicious':
        return <X className="text-red-500" size={24} />;
      case 'critical':
        return <Bug className="text-red-600" size={24} />;
    }
  };

  const getThreatColor = () => {
    switch (result.threatLevel) {
      case 'safe': return 'green';
      case 'suspicious': return 'amber';
      case 'malicious': return 'red';
      case 'critical': return 'red';
    }
  };

  const getThreatBgColor = () => {
    switch (result.threatLevel) {
      case 'safe': return 'bg-green-50 border-green-200';
      case 'suspicious': return 'bg-amber-50 border-amber-200';
      case 'malicious': return 'bg-red-50 border-red-200';
      case 'critical': return 'bg-red-100 border-red-300';
    }
  };

  const getVulnerabilityIcon = (type: string) => {
    switch (type) {
      case 'xss': return <Code className="text-orange-500" size={16} />;
      case 'sql_injection': return <Database className="text-red-500" size={16} />;
      case 'otp_bypass': return <Lock className="text-purple-500" size={16} />;
      case 'csrf': return <Shield className="text-blue-500" size={16} />;
      case 'session_hijack': return <Eye className="text-indigo-500" size={16} />;
      case 'clickjacking': return <Activity className="text-pink-500" size={16} />;
      default: return <Bug className="text-gray-500" size={16} />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low': return 'bg-blue-100 text-blue-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      case 'high': return 'bg-orange-100 text-orange-800';
      case 'critical': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getThreatTypeIcon = (type: string) => {
    switch (type) {
      case 'malware': return <Bug className="text-red-500" size={16} />;
      case 'phishing': return <Shield className="text-orange-500" size={16} />;
      case 'tracking': return <Eye className="text-blue-500" size={16} />;
      case 'injection': return <Code className="text-purple-500" size={16} />;
      case 'redirect': return <Globe className="text-green-500" size={16} />;
      default: return <AlertTriangle className="text-gray-500" size={16} />;
    }
  };

  const color = getThreatColor();
  const bgColor = getThreatBgColor();

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Shield },
    { id: 'vulnerabilities', label: `Vulnerabilities (${result.vulnerabilities.length})`, icon: Bug },
    { id: 'crawler', label: 'Crawler Analysis', icon: Globe },
    { id: 'realtime', label: `Real-time Threats (${result.realTimeThreats.length})`, icon: Zap }
  ];

  return (
    <div className="space-y-6">
      {/* Overall Result */}
      <div className={`rounded-xl border-2 ${bgColor} p-6`}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            {getThreatIcon()}
            <div>
              <h3 className="text-xl font-semibold text-gray-800">
                {result.threatLevel.charAt(0).toUpperCase() + result.threatLevel.slice(1)} Threat Level
              </h3>
              <p className="text-sm text-gray-600">
                Risk Score: {result.score}/{result.maxScore} | Vulnerabilities: {result.vulnerabilities.length} | Real-time Threats: {result.realTimeThreats.length}
              </p>
            </div>
          </div>
          <div className={`text-${color}-600 font-mono text-sm`}>
            {new Date(result.timestamp).toLocaleTimeString()}
          </div>
        </div>

        <div className="mb-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700">Threat Level</span>
            <span className="text-sm text-gray-600">
              {Math.round((result.score / result.maxScore) * 100)}%
            </span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-3">
            <div
              className={`h-3 rounded-full bg-${color}-500 transition-all duration-500`}
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

        {/* Quick Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white bg-opacity-50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-gray-800">{result.checks.length}</div>
            <div className="text-xs text-gray-600">Security Checks</div>
          </div>
          <div className="bg-white bg-opacity-50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-red-600">{result.vulnerabilities.length}</div>
            <div className="text-xs text-gray-600">Vulnerabilities</div>
          </div>
          <div className="bg-white bg-opacity-50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-orange-600">{result.realTimeThreats.length}</div>
            <div className="text-xs text-gray-600">Active Threats</div>
          </div>
          <div className="bg-white bg-opacity-50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-blue-600">{result.crawlerResults?.pagesScanned || 0}</div>
            <div className="text-xs text-gray-600">Pages Scanned</div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white rounded-xl shadow-lg overflow-hidden">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
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
                </button>
              );
            })}
          </nav>
        </div>

        <div className="p-6">
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Security Checks */}
              <div>
                <h4 className="text-lg font-semibold text-gray-800 mb-4">Security Analysis</h4>
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
                            <div className="flex items-center space-x-2">
                              <span className={`text-xs px-2 py-1 rounded-full ${
                                check.category === 'injection' ? 'bg-red-100 text-red-800' :
                                check.category === 'authentication' ? 'bg-purple-100 text-purple-800' :
                                check.category === 'behavior' ? 'bg-orange-100 text-orange-800' :
                                check.category === 'content' ? 'bg-blue-100 text-blue-800' :
                                'bg-gray-100 text-gray-800'
                              }`}>
                                {check.category.toUpperCase()}
                              </span>
                              {check.weight > 0 && (
                                <span className={`text-xs px-2 py-1 rounded-full ${
                                  check.passed ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                                }`}>
                                  {check.passed ? 'PASS' : `FAIL (-${check.weight})`}
                                </span>
                              )}
                            </div>
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
              <div>
                <h4 className="text-lg font-semibold text-gray-800 mb-4">Security Recommendations</h4>
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
          )}

          {/* Vulnerabilities Tab */}
          {activeTab === 'vulnerabilities' && (
            <div className="space-y-4">
              <h4 className="text-lg font-semibold text-gray-800">Detected Vulnerabilities</h4>
              {result.vulnerabilities.length === 0 ? (
                <div className="text-center py-8">
                  <Shield className="mx-auto text-green-500 mb-2" size={48} />
                  <p className="text-gray-500">No vulnerabilities detected</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {result.vulnerabilities.map((vuln, index) => (
                    <div key={index} className="border border-red-200 rounded-lg p-4 bg-red-50">
                      <div className="flex items-start space-x-3">
                        {getVulnerabilityIcon(vuln.type)}
                        <div className="flex-1">
                          <div className="flex items-center justify-between mb-2">
                            <h5 className="font-semibold text-gray-800">
                              {vuln.type.replace('_', ' ').toUpperCase()} Vulnerability
                            </h5>
                            <span className={`text-xs px-2 py-1 rounded-full ${getSeverityColor(vuln.severity)}`}>
                              {vuln.severity.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-sm text-gray-700 mb-2">{vuln.description}</p>
                          {vuln.payload && (
                            <div className="mb-2">
                              <p className="text-xs text-gray-600 mb-1">Detected Payload:</p>
                              <code className="text-xs bg-gray-100 p-2 rounded block font-mono">
                                {vuln.payload}
                              </code>
                            </div>
                          )}
                          <div className="mb-2">
                            <p className="text-xs text-gray-600 mb-1">Mitigation:</p>
                            <p className="text-xs text-gray-700">{vuln.mitigation}</p>
                          </div>
                          {vuln.cve && (
                            <p className="text-xs text-blue-600">CVE Reference: {vuln.cve}</p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Crawler Tab */}
          {activeTab === 'crawler' && (
            <div className="space-y-6">
              <h4 className="text-lg font-semibold text-gray-800">Web Crawler Analysis</h4>
              {result.crawlerResults ? (
                <div className="space-y-6">
                  {/* Crawler Stats */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-blue-50 rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-blue-600">{result.crawlerResults.pagesScanned}</div>
                      <div className="text-sm text-gray-600">Pages Scanned</div>
                    </div>
                    <div className="bg-green-50 rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-green-600">{result.crawlerResults.linksFound}</div>
                      <div className="text-sm text-gray-600">Links Found</div>
                    </div>
                    <div className="bg-orange-50 rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-orange-600">{result.crawlerResults.formsAnalyzed}</div>
                      <div className="text-sm text-gray-600">Forms Analyzed</div>
                    </div>
                    <div className="bg-purple-50 rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-purple-600">{result.crawlerResults.scriptsDetected}</div>
                      <div className="text-sm text-gray-600">Scripts Detected</div>
                    </div>
                  </div>

                  {/* Suspicious Patterns */}
                  <div>
                    <h5 className="font-semibold text-gray-800 mb-3">Suspicious Patterns</h5>
                    <div className="space-y-3">
                      {result.crawlerResults.suspiciousPatterns.map((pattern, index) => (
                        <div key={index} className={`p-3 rounded-lg border ${
                          pattern.riskLevel === 'high' ? 'bg-red-50 border-red-200' :
                          pattern.riskLevel === 'medium' ? 'bg-orange-50 border-orange-200' :
                          'bg-yellow-50 border-yellow-200'
                        }`}>
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-medium text-gray-800">{pattern.type}</span>
                            <span className={`text-xs px-2 py-1 rounded-full ${
                              pattern.riskLevel === 'high' ? 'bg-red-100 text-red-800' :
                              pattern.riskLevel === 'medium' ? 'bg-orange-100 text-orange-800' :
                              'bg-yellow-100 text-yellow-800'
                            }`}>
                              {pattern.riskLevel.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-sm text-gray-600 mb-1">{pattern.description}</p>
                          <p className="text-xs text-gray-500">Location: {pattern.location}</p>
                          <code className="text-xs bg-gray-100 p-1 rounded mt-1 block">{pattern.pattern}</code>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Network Requests */}
                  <div>
                    <h5 className="font-semibold text-gray-800 mb-3">Network Requests Analysis</h5>
                    <div className="space-y-2">
                      {result.crawlerResults.networkRequests.map((request, index) => (
                        <div key={index} className={`p-3 rounded-lg border ${
                          request.suspicious ? 'bg-red-50 border-red-200' : 'bg-green-50 border-green-200'
                        }`}>
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-mono text-sm">{request.method}</span>
                            <span className={`text-xs px-2 py-1 rounded-full ${
                              request.suspicious ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                            }`}>
                              {request.suspicious ? 'SUSPICIOUS' : 'SAFE'}
                            </span>
                          </div>
                          <p className="text-sm text-gray-700 break-all">{request.url}</p>
                          {request.reason && (
                            <p className="text-xs text-red-600 mt-1">{request.reason}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8">
                  <Globe className="mx-auto text-gray-400 mb-2" size={48} />
                  <p className="text-gray-500">Crawler analysis not performed</p>
                </div>
              )}
            </div>
          )}

          {/* Real-time Threats Tab */}
          {activeTab === 'realtime' && (
            <div className="space-y-4">
              <h4 className="text-lg font-semibold text-gray-800">Real-time Threat Detection</h4>
              {result.realTimeThreats.length === 0 ? (
                <div className="text-center py-8">
                  <Zap className="mx-auto text-green-500 mb-2" size={48} />
                  <p className="text-gray-500">No real-time threats detected</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {result.realTimeThreats.map((threat, index) => (
                    <div key={index} className={`p-4 rounded-lg border ${
                      threat.severity === 'critical' ? 'bg-red-100 border-red-300' :
                      threat.severity === 'high' ? 'bg-red-50 border-red-200' :
                      threat.severity === 'medium' ? 'bg-orange-50 border-orange-200' :
                      'bg-yellow-50 border-yellow-200'
                    }`}>
                      <div className="flex items-start space-x-3">
                        {getThreatTypeIcon(threat.type)}
                        <div className="flex-1">
                          <div className="flex items-center justify-between mb-2">
                            <h5 className="font-semibold text-gray-800">
                              {threat.type.replace('_', ' ').toUpperCase()} Threat
                            </h5>
                            <div className="flex items-center space-x-2">
                              <span className={`text-xs px-2 py-1 rounded-full ${getSeverityColor(threat.severity)}`}>
                                {threat.severity.toUpperCase()}
                              </span>
                              <span className={`text-xs px-2 py-1 rounded-full ${
                                threat.blocked ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                              }`}>
                                {threat.blocked ? 'BLOCKED' : 'DETECTED'}
                              </span>
                            </div>
                          </div>
                          <p className="text-sm text-gray-700 mb-2">{threat.description}</p>
                          <div className="flex items-center justify-between text-xs text-gray-500">
                            <span>Source: {threat.source}</span>
                            <span>{new Date(threat.timestamp).toLocaleTimeString()}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};