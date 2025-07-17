export interface AnalysisResult {
  url: string;
  threatLevel: 'safe' | 'suspicious' | 'malicious' | 'critical';
  score: number;
  maxScore: number;
  checks: SecurityCheck[];
  timestamp: number;
  recommendations: string[];
  vulnerabilities: Vulnerability[];
  realTimeThreats: RealTimeThreat[];
  httpStatus?: number;
  responseTime?: number;
  contentAnalysis?: ContentAnalysis;
  networkSecurity?: NetworkSecurity;
}

export interface SecurityCheck {
  name: string;
  description: string;
  passed: boolean;
  weight: number;
  details?: string;
  category: 'url' | 'content' | 'network' | 'headers' | 'ssl' | 'behavior';
  actualResult?: any;
}

export interface Vulnerability {
  type: 'xss' | 'sql_injection' | 'csrf' | 'clickjacking' | 'mixed_content' | 'insecure_headers' | 'ssl_issues';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence?: string;
  location?: string;
  mitigation: string;
  cve?: string;
}

export interface RealTimeThreat {
  type: 'malware' | 'phishing' | 'tracking' | 'suspicious_redirect' | 'data_harvesting';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  timestamp: number;
  blocked: boolean;
  evidence: string;
  source: string;
}

export interface ContentAnalysis {
  hasJavaScript: boolean;
  hasIframes: boolean;
  hasForms: boolean;
  hasExternalLinks: boolean;
  suspiciousPatterns: string[];
  hiddenElements: number;
  scriptSources: string[];
  formActions: string[];
}

export interface NetworkSecurity {
  httpsEnabled: boolean;
  validCertificate: boolean;
  securityHeaders: SecurityHeaders;
  redirectChain: string[];
  ipAddress?: string;
  location?: string;
}

export interface SecurityHeaders {
  contentSecurityPolicy: boolean;
  xFrameOptions: boolean;
  xContentTypeOptions: boolean;
  strictTransportSecurity: boolean;
  xXSSProtection: boolean;
}

export interface ScanHistory {
  id: string;
  url: string;
  threatLevel: 'safe' | 'suspicious' | 'malicious' | 'critical';
  timestamp: number;
  score: number;
  vulnerabilities: number;
  realTimeThreats: number;
  responseTime: number;
}

export interface SystemStatus {
  isActive: boolean;
  threatsBlocked: number;
  sitesAnalyzed: number;
  lastActivity: number;
  protectionLevel: 'basic' | 'enhanced' | 'maximum';
}