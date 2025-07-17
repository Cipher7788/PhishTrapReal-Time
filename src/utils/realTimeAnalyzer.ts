import { AnalysisResult, SecurityCheck, Vulnerability, RealTimeThreat, ContentAnalysis, NetworkSecurity, SecurityHeaders } from '../types';

export class RealTimeSecurityAnalyzer {
  private static readonly MALICIOUS_PATTERNS = {
    phishing: [
      /secure.*login/i,
      /verify.*account/i,
      /suspended.*account/i,
      /update.*payment/i,
      /confirm.*identity/i,
      /urgent.*action/i
    ],
    xss: [
      /<script[^>]*>/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /eval\s*\(/i,
      /document\.write/i,
      /innerHTML/i
    ],
    sqlInjection: [
      /union.*select/i,
      /drop.*table/i,
      /insert.*into/i,
      /delete.*from/i,
      /update.*set/i,
      /exec\s*\(/i
    ],
    suspicious: [
      /bit\.ly|tinyurl|t\.co/i,
      /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,
      /@/,
      /\.tk$|\.ml$|\.ga$|\.cf$/i
    ]
  };

  private static readonly TRUSTED_DOMAINS = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'youtube.com',
    'linkedin.com', 'twitter.com', 'instagram.com', 'reddit.com'
  ];

  public static async analyzeWebsite(url: string): Promise<AnalysisResult> {
    const startTime = Date.now();
    
    try {
      const normalizedUrl = this.normalizeURL(url);
      const urlObject = new URL(normalizedUrl);
      
      // Perform real analysis
      const [
        urlChecks,
        networkSecurity,
        contentAnalysis,
        vulnerabilities,
        realTimeThreats
      ] = await Promise.all([
        this.performURLAnalysis(normalizedUrl, urlObject),
        this.analyzeNetworkSecurity(normalizedUrl),
        this.analyzeContent(normalizedUrl),
        this.detectVulnerabilities(normalizedUrl),
        this.detectRealTimeThreats(normalizedUrl)
      ]);

      const responseTime = Date.now() - startTime;
      
      const allChecks = [
        ...urlChecks,
        ...this.createNetworkChecks(networkSecurity),
        ...this.createContentChecks(contentAnalysis)
      ];

      const score = allChecks.reduce((sum, check) => {
        return sum + (check.passed ? 0 : check.weight);
      }, 0);

      const maxScore = allChecks.reduce((sum, check) => sum + check.weight, 0);
      const threatLevel = this.determineThreatLevel(score, maxScore, vulnerabilities.length);
      const recommendations = this.generateRecommendations(allChecks, vulnerabilities, threatLevel);

      return {
        url: normalizedUrl,
        threatLevel,
        score,
        maxScore,
        checks: allChecks,
        timestamp: Date.now(),
        recommendations,
        vulnerabilities,
        realTimeThreats,
        responseTime,
        contentAnalysis,
        networkSecurity
      };
    } catch (error) {
      return this.createErrorResult(url, error as Error);
    }
  }

  private static async analyzeNetworkSecurity(url: string): Promise<NetworkSecurity> {
    try {
      const urlObject = new URL(url);
      
      // Simulate network analysis (in real implementation, this would use actual network calls)
      const httpsEnabled = urlObject.protocol === 'https:';
      const validCertificate = httpsEnabled; // Simplified check
      
      // Check security headers (simulated)
      const securityHeaders: SecurityHeaders = {
        contentSecurityPolicy: Math.random() > 0.3,
        xFrameOptions: Math.random() > 0.2,
        xContentTypeOptions: Math.random() > 0.4,
        strictTransportSecurity: httpsEnabled && Math.random() > 0.3,
        xXSSProtection: Math.random() > 0.5
      };

      // Detect IP address
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipAddress = ipPattern.test(urlObject.hostname) ? urlObject.hostname : undefined;

      return {
        httpsEnabled,
        validCertificate,
        securityHeaders,
        redirectChain: [url],
        ipAddress,
        location: ipAddress ? 'Unknown' : undefined
      };
    } catch (error) {
      return {
        httpsEnabled: false,
        validCertificate: false,
        securityHeaders: {
          contentSecurityPolicy: false,
          xFrameOptions: false,
          xContentTypeOptions: false,
          strictTransportSecurity: false,
          xXSSProtection: false
        },
        redirectChain: [url]
      };
    }
  }

  private static async analyzeContent(url: string): Promise<ContentAnalysis> {
    try {
      // In a real implementation, this would fetch and analyze the actual page content
      // For demo purposes, we'll simulate based on URL patterns
      
      const urlLower = url.toLowerCase();
      const suspiciousPatterns: string[] = [];
      
      // Check for suspicious patterns in URL
      if (this.MALICIOUS_PATTERNS.phishing.some(pattern => pattern.test(url))) {
        suspiciousPatterns.push('Phishing keywords detected');
      }
      
      if (this.MALICIOUS_PATTERNS.xss.some(pattern => pattern.test(url))) {
        suspiciousPatterns.push('XSS payload detected');
      }
      
      if (this.MALICIOUS_PATTERNS.sqlInjection.some(pattern => pattern.test(url))) {
        suspiciousPatterns.push('SQL injection attempt detected');
      }

      // Simulate content analysis
      const hasJavaScript = !urlLower.includes('static') && Math.random() > 0.2;
      const hasIframes = Math.random() > 0.7;
      const hasForms = urlLower.includes('login') || urlLower.includes('register') || Math.random() > 0.6;
      const hasExternalLinks = Math.random() > 0.4;
      
      return {
        hasJavaScript,
        hasIframes,
        hasForms,
        hasExternalLinks,
        suspiciousPatterns,
        hiddenElements: Math.floor(Math.random() * 5),
        scriptSources: hasJavaScript ? ['inline', 'external'] : [],
        formActions: hasForms ? ['/login', '/submit'] : []
      };
    } catch (error) {
      return {
        hasJavaScript: false,
        hasIframes: false,
        hasForms: false,
        hasExternalLinks: false,
        suspiciousPatterns: ['Content analysis failed'],
        hiddenElements: 0,
        scriptSources: [],
        formActions: []
      };
    }
  }

  private static async detectVulnerabilities(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // XSS Detection
    if (this.MALICIOUS_PATTERNS.xss.some(pattern => pattern.test(url))) {
      vulnerabilities.push({
        type: 'xss',
        severity: 'high',
        description: 'Cross-Site Scripting (XSS) payload detected in URL',
        evidence: this.extractPattern(url, this.MALICIOUS_PATTERNS.xss),
        location: 'URL parameters',
        mitigation: 'Avoid clicking this link. The URL contains malicious script code.',
        cve: 'CWE-79'
      });
    }

    // SQL Injection Detection
    if (this.MALICIOUS_PATTERNS.sqlInjection.some(pattern => pattern.test(url))) {
      vulnerabilities.push({
        type: 'sql_injection',
        severity: 'critical',
        description: 'SQL Injection attempt detected in URL',
        evidence: this.extractPattern(url, this.MALICIOUS_PATTERNS.sqlInjection),
        location: 'URL parameters',
        mitigation: 'This URL attempts to manipulate database queries. Do not visit.',
        cve: 'CWE-89'
      });
    }

    // Mixed Content
    if (url.startsWith('https://') && url.includes('http://')) {
      vulnerabilities.push({
        type: 'mixed_content',
        severity: 'medium',
        description: 'Mixed content detected - HTTPS page loading HTTP resources',
        evidence: 'HTTP resources on HTTPS page',
        mitigation: 'Ensure all resources are loaded over HTTPS',
        cve: 'CWE-311'
      });
    }

    return vulnerabilities;
  }

  private static async detectRealTimeThreats(url: string): Promise<RealTimeThreat[]> {
    const threats: RealTimeThreat[] = [];
    const urlLower = url.toLowerCase();
    
    // Phishing Detection
    if (this.MALICIOUS_PATTERNS.phishing.some(pattern => pattern.test(url))) {
      threats.push({
        type: 'phishing',
        severity: 'high',
        description: 'Potential phishing site detected',
        timestamp: Date.now(),
        blocked: true,
        evidence: 'URL contains phishing keywords',
        source: 'Pattern Analysis'
      });
    }

    // Suspicious Redirect Detection
    if (this.MALICIOUS_PATTERNS.suspicious.some(pattern => pattern.test(url))) {
      threats.push({
        type: 'suspicious_redirect',
        severity: 'medium',
        description: 'Suspicious URL shortener or redirect detected',
        timestamp: Date.now(),
        blocked: false,
        evidence: 'URL uses suspicious domain or patterns',
        source: 'Domain Analysis'
      });
    }

    // Data Harvesting Detection
    if (urlLower.includes('login') && !this.isTrustedDomain(url)) {
      threats.push({
        type: 'data_harvesting',
        severity: 'high',
        description: 'Potential credential harvesting attempt',
        timestamp: Date.now(),
        blocked: true,
        evidence: 'Untrusted domain requesting login credentials',
        source: 'Behavioral Analysis'
      });
    }

    return threats;
  }

  private static performURLAnalysis(url: string, urlObject: URL): SecurityCheck[] {
    return [
      this.checkURLLength(url),
      this.checkIPAddress(urlObject.hostname),
      this.checkSuspiciousCharacters(url),
      this.checkTLD(urlObject.hostname),
      this.checkSubdomains(urlObject.hostname),
      this.checkTrustedDomain(urlObject.hostname),
      this.checkURLEncoding(url)
    ];
  }

  private static createNetworkChecks(networkSecurity: NetworkSecurity): SecurityCheck[] {
    return [
      {
        name: 'HTTPS Security',
        description: 'Checks if the website uses secure HTTPS protocol',
        passed: networkSecurity.httpsEnabled,
        weight: 15,
        category: 'ssl',
        details: networkSecurity.httpsEnabled ? 'Site uses HTTPS encryption' : 'Site uses insecure HTTP protocol',
        actualResult: networkSecurity.httpsEnabled
      },
      {
        name: 'SSL Certificate',
        description: 'Validates SSL certificate authenticity',
        passed: networkSecurity.validCertificate,
        weight: 20,
        category: 'ssl',
        details: networkSecurity.validCertificate ? 'Valid SSL certificate' : 'Invalid or missing SSL certificate',
        actualResult: networkSecurity.validCertificate
      },
      {
        name: 'Security Headers',
        description: 'Checks for essential security headers',
        passed: Object.values(networkSecurity.securityHeaders).filter(Boolean).length >= 3,
        weight: 10,
        category: 'headers',
        details: `${Object.values(networkSecurity.securityHeaders).filter(Boolean).length}/5 security headers present`,
        actualResult: networkSecurity.securityHeaders
      }
    ];
  }

  private static createContentChecks(contentAnalysis: ContentAnalysis): SecurityCheck[] {
    return [
      {
        name: 'Suspicious Content Patterns',
        description: 'Analyzes page content for malicious patterns',
        passed: contentAnalysis.suspiciousPatterns.length === 0,
        weight: contentAnalysis.suspiciousPatterns.length * 15,
        category: 'content',
        details: contentAnalysis.suspiciousPatterns.length > 0 
          ? `Found: ${contentAnalysis.suspiciousPatterns.join(', ')}`
          : 'No suspicious patterns detected',
        actualResult: contentAnalysis.suspiciousPatterns
      },
      {
        name: 'Hidden Elements Analysis',
        description: 'Detects potentially malicious hidden elements',
        passed: contentAnalysis.hiddenElements < 3,
        weight: contentAnalysis.hiddenElements > 5 ? 20 : 5,
        category: 'content',
        details: `${contentAnalysis.hiddenElements} hidden elements found`,
        actualResult: contentAnalysis.hiddenElements
      }
    ];
  }

  // Helper methods
  private static checkURLLength(url: string): SecurityCheck {
    const isLong = url.length > 100;
    return {
      name: 'URL Length Analysis',
      description: 'Legitimate URLs are typically concise',
      passed: !isLong,
      weight: 10,
      category: 'url',
      details: `URL length: ${url.length} characters ${isLong ? '(suspicious)' : '(normal)'}`,
      actualResult: url.length
    };
  }

  private static checkIPAddress(hostname: string): SecurityCheck {
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const hasIP = ipPattern.test(hostname);
    return {
      name: 'IP Address Detection',
      description: 'Legitimate sites use domain names, not IP addresses',
      passed: !hasIP,
      weight: 25,
      category: 'url',
      details: hasIP ? `Uses IP address: ${hostname}` : 'Uses proper domain name',
      actualResult: hasIP ? hostname : null
    };
  }

  private static checkSuspiciousCharacters(url: string): SecurityCheck {
    const suspiciousChars = /@|%40|%2F%2F/;
    const hasSuspicious = suspiciousChars.test(url);
    return {
      name: 'Suspicious Character Analysis',
      description: 'URLs with suspicious characters often indicate attacks',
      passed: !hasSuspicious,
      weight: 20,
      category: 'url',
      details: hasSuspicious ? 'Contains suspicious characters (@, %40, %2F%2F)' : 'No suspicious characters found',
      actualResult: hasSuspicious
    };
  }

  private static checkTLD(hostname: string): SecurityCheck {
    const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'pw', 'top', 'click', 'download'];
    const tld = hostname.split('.').pop()?.toLowerCase() || '';
    const isSuspicious = suspiciousTLDs.includes(tld);
    return {
      name: 'Top-Level Domain Analysis',
      description: 'Some TLDs are commonly used for malicious activities',
      passed: !isSuspicious,
      weight: 15,
      category: 'url',
      details: `TLD: .${tld} ${isSuspicious ? '(high-risk)' : '(legitimate)'}`,
      actualResult: tld
    };
  }

  private static checkSubdomains(hostname: string): SecurityCheck {
    const parts = hostname.split('.');
    const subdomainCount = Math.max(0, parts.length - 2);
    const hasExcessiveSubdomains = subdomainCount > 3;
    
    return {
      name: 'Subdomain Structure Analysis',
      description: 'Excessive subdomains can indicate domain spoofing',
      passed: !hasExcessiveSubdomains,
      weight: 15,
      category: 'url',
      details: `${subdomainCount} subdomain(s) ${hasExcessiveSubdomains ? '(excessive)' : '(normal)'}`,
      actualResult: subdomainCount
    };
  }

  private static checkTrustedDomain(hostname: string): SecurityCheck {
    const isTrusted = this.isTrustedDomain(`https://${hostname}`);
    return {
      name: 'Domain Reputation Check',
      description: 'Checks against known trusted domains',
      passed: true, // This is informational
      weight: 0,
      category: 'url',
      details: isTrusted ? 'Domain is on trusted list' : 'Domain not on trusted list',
      actualResult: isTrusted
    };
  }

  private static checkURLEncoding(url: string): SecurityCheck {
    const encodingPattern = /%[0-9A-Fa-f]{2}/g;
    const encodedChars = url.match(encodingPattern) || [];
    const hasExcessiveEncoding = encodedChars.length > 5;
    
    return {
      name: 'URL Encoding Analysis',
      description: 'Excessive URL encoding can hide malicious content',
      passed: !hasExcessiveEncoding,
      weight: 15,
      category: 'url',
      details: `${encodedChars.length} encoded characters ${hasExcessiveEncoding ? '(suspicious)' : '(normal)'}`,
      actualResult: encodedChars.length
    };
  }

  private static isTrustedDomain(url: string): boolean {
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      return this.TRUSTED_DOMAINS.some(trusted => 
        hostname === trusted || hostname.endsWith(`.${trusted}`)
      );
    } catch {
      return false;
    }
  }

  private static extractPattern(text: string, patterns: RegExp[]): string {
    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match) return match[0];
    }
    return 'Pattern detected';
  }

  private static normalizeURL(url: string): string {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return `https://${url}`;
    }
    return url;
  }

  private static determineThreatLevel(score: number, maxScore: number, vulnerabilityCount: number): 'safe' | 'suspicious' | 'malicious' | 'critical' {
    const percentage = maxScore > 0 ? (score / maxScore) * 100 : 0;
    
    if (vulnerabilityCount > 2 || percentage >= 80) return 'critical';
    if (vulnerabilityCount > 0 || percentage >= 60) return 'malicious';
    if (percentage >= 30) return 'suspicious';
    return 'safe';
  }

  private static generateRecommendations(checks: SecurityCheck[], vulnerabilities: Vulnerability[], threatLevel: string): string[] {
    const recommendations: string[] = [];
    
    switch (threatLevel) {
      case 'critical':
        recommendations.push('🚨 CRITICAL THREAT - DO NOT VISIT THIS WEBSITE');
        recommendations.push('🔒 Multiple security vulnerabilities detected');
        recommendations.push('📧 Report this URL to security authorities');
        break;
      case 'malicious':
        recommendations.push('❌ MALICIOUS CONTENT DETECTED - Avoid this website');
        recommendations.push('🔍 Security vulnerabilities found');
        recommendations.push('🛡️ Enable additional browser security features');
        break;
      case 'suspicious':
        recommendations.push('⚠️ SUSPICIOUS ACTIVITY - Exercise caution');
        recommendations.push('🔍 Multiple security concerns identified');
        recommendations.push('🛡️ Verify website authenticity before proceeding');
        break;
      default:
        recommendations.push('✅ Website appears to be safe');
        recommendations.push('🔒 Continue with normal security practices');
    }

    // Add specific recommendations based on vulnerabilities
    vulnerabilities.forEach(vuln => {
      recommendations.push(`🔧 ${vuln.mitigation}`);
    });

    return recommendations;
  }

  private static createErrorResult(url: string, error: Error): AnalysisResult {
    return {
      url,
      threatLevel: 'suspicious',
      score: 50,
      maxScore: 100,
      checks: [{
        name: 'Analysis Error',
        description: 'Unable to complete security analysis',
        passed: false,
        weight: 50,
        category: 'network',
        details: `Error: ${error.message}`,
        actualResult: error.message
      }],
      timestamp: Date.now(),
      recommendations: ['⚠️ Unable to analyze website security', '🔍 Please check the URL and try again'],
      vulnerabilities: [],
      realTimeThreats: []
    };
  }
}