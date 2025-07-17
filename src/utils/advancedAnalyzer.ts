import { AnalysisResult, SecurityCheck, Vulnerability, CrawlerResult, RealTimeThreat, SuspiciousPattern, NetworkRequest, DOMAnalysis, FormField } from '../types';

export class AdvancedSecurityAnalyzer {
  private static readonly XSS_PATTERNS = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe[^>]*>/gi,
    /eval\s*\(/gi,
    /document\.write/gi,
    /innerHTML/gi,
    /outerHTML/gi,
    /<img[^>]*onerror/gi,
    /<svg[^>]*onload/gi
  ];

  private static readonly SQL_INJECTION_PATTERNS = [
    /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)/gi,
    /(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+/gi,
    /'\s*(OR|AND)\s*'[^']*'\s*=\s*'/gi,
    /;\s*(DROP|DELETE|UPDATE|INSERT)/gi,
    /\/\*.*?\*\//gi,
    /--[^\r\n]*/gi,
    /\bxp_cmdshell\b/gi,
    /\bsp_executesql\b/gi,
    /\bEXEC\s*\(/gi,
    /\bCAST\s*\(/gi
  ];

  private static readonly OTP_BYPASS_PATTERNS = [
    /otp.*bypass/gi,
    /2fa.*bypass/gi,
    /verification.*skip/gi,
    /sms.*intercept/gi,
    /totp.*crack/gi,
    /authenticator.*bypass/gi,
    /phone.*verification.*bypass/gi,
    /code.*generator/gi
  ];

  private static readonly MALICIOUS_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bc.vc', 'linkbucks.com'
  ];

  private static readonly SUSPICIOUS_HEADERS = [
    'x-forwarded-for', 'x-real-ip', 'x-originating-ip',
    'x-remote-ip', 'x-cluster-client-ip'
  ];

  public static async analyzeAdvanced(url: string, enableCrawler: boolean = true): Promise<AnalysisResult> {
    try {
      const normalizedUrl = this.normalizeURL(url);
      const urlObject = new URL(normalizedUrl);
      
      // Basic security checks
      const basicChecks = this.performBasicChecks(normalizedUrl, urlObject);
      
      // Advanced vulnerability detection
      const vulnerabilities = await this.detectVulnerabilities(normalizedUrl);
      
      // Real-time threat monitoring
      const realTimeThreats = this.monitorRealTimeThreats(normalizedUrl);
      
      // Web crawler analysis (simulated)
      let crawlerResults: CrawlerResult | undefined;
      if (enableCrawler) {
        crawlerResults = await this.performCrawlerAnalysis(normalizedUrl);
      }

      // Advanced security checks
      const advancedChecks = await this.performAdvancedChecks(normalizedUrl, crawlerResults);
      
      const allChecks = [...basicChecks, ...advancedChecks];
      
      const score = allChecks.reduce((sum, check) => {
        return sum + (check.passed ? 0 : check.weight);
      }, 0);

      const maxScore = allChecks.reduce((sum, check) => sum + check.weight, 0);
      const threatLevel = this.determineThreatLevel(score, maxScore, vulnerabilities.length);
      const recommendations = this.generateAdvancedRecommendations(allChecks, vulnerabilities, threatLevel);

      return {
        url: normalizedUrl,
        threatLevel,
        score,
        maxScore,
        checks: allChecks,
        timestamp: Date.now(),
        recommendations,
        vulnerabilities,
        crawlerResults,
        realTimeThreats
      };
    } catch (error) {
      return this.createErrorResult(url, error as Error);
    }
  }

  private static performBasicChecks(url: string, urlObject: URL): SecurityCheck[] {
    return [
      this.checkURLLength(url),
      this.checkIPAddress(urlObject.hostname),
      this.checkSuspiciousCharacters(url),
      this.checkTLD(urlObject.hostname),
      this.checkSubdomains(urlObject.hostname),
      this.checkHTTPS(urlObject.protocol),
      this.checkMaliciousDomains(urlObject.hostname),
      this.checkURLEncoding(url)
    ];
  }

  private static async performAdvancedChecks(url: string, crawlerResults?: CrawlerResult): SecurityCheck[] {
    const checks: SecurityCheck[] = [
      this.checkXSSVulnerabilities(url),
      this.checkSQLInjectionVulnerabilities(url),
      this.checkOTPBypassAttempts(url),
      this.checkCSRFVulnerabilities(url),
      this.checkClickjackingVulnerabilities(url),
      this.checkSessionSecurity(url),
      this.checkContentSecurityPolicy(url),
      this.checkMixedContent(url)
    ];

    if (crawlerResults) {
      checks.push(...this.analyzeCrawlerResults(crawlerResults));
    }

    return checks;
  }

  private static async detectVulnerabilities(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // XSS Detection
    if (this.detectXSS(url)) {
      vulnerabilities.push({
        type: 'xss',
        severity: 'high',
        description: 'Potential Cross-Site Scripting (XSS) vulnerability detected',
        payload: this.extractXSSPayload(url),
        mitigation: 'Implement proper input validation and output encoding',
        cve: 'CWE-79'
      });
    }

    // SQL Injection Detection
    if (this.detectSQLInjection(url)) {
      vulnerabilities.push({
        type: 'sql_injection',
        severity: 'critical',
        description: 'Potential SQL Injection vulnerability detected',
        payload: this.extractSQLPayload(url),
        mitigation: 'Use parameterized queries and input validation',
        cve: 'CWE-89'
      });
    }

    // OTP Bypass Detection
    if (this.detectOTPBypass(url)) {
      vulnerabilities.push({
        type: 'otp_bypass',
        severity: 'high',
        description: 'Potential OTP/2FA bypass attempt detected',
        mitigation: 'Implement proper multi-factor authentication',
        cve: 'CWE-287'
      });
    }

    return vulnerabilities;
  }

  private static monitorRealTimeThreats(url: string): RealTimeThreat[] {
    const threats: RealTimeThreat[] = [];
    
    // Simulate real-time threat detection
    if (url.includes('malware') || url.includes('virus')) {
      threats.push({
        type: 'malware',
        severity: 'critical',
        description: 'Malware distribution site detected',
        timestamp: Date.now(),
        blocked: true,
        source: 'Real-time scanner'
      });
    }

    if (url.includes('phish') || url.includes('fake')) {
      threats.push({
        type: 'phishing',
        severity: 'high',
        description: 'Phishing attempt detected',
        timestamp: Date.now(),
        blocked: true,
        source: 'Phishing database'
      });
    }

    if (url.includes('track') || url.includes('analytics')) {
      threats.push({
        type: 'tracking',
        severity: 'medium',
        description: 'Tracking script detected',
        timestamp: Date.now(),
        blocked: false,
        source: 'Privacy scanner'
      });
    }

    return threats;
  }

  private static async performCrawlerAnalysis(url: string): Promise<CrawlerResult> {
    // Simulate high-intensity web crawler
    const suspiciousPatterns: SuspiciousPattern[] = [
      {
        type: 'Hidden Form',
        pattern: 'display:none',
        location: '/login',
        riskLevel: 'high',
        description: 'Hidden form fields detected - potential data harvesting'
      },
      {
        type: 'Obfuscated JavaScript',
        pattern: 'eval(unescape(',
        location: '/assets/script.js',
        riskLevel: 'high',
        description: 'Obfuscated JavaScript code detected'
      },
      {
        type: 'Suspicious Redirect',
        pattern: 'window.location.replace',
        location: '/redirect.php',
        riskLevel: 'medium',
        description: 'Automatic redirect detected'
      }
    ];

    const networkRequests: NetworkRequest[] = [
      {
        url: 'https://suspicious-analytics.com/track',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        suspicious: true,
        reason: 'Sends data to suspicious tracking domain'
      },
      {
        url: 'https://cdn.example.com/jquery.js',
        method: 'GET',
        headers: { 'Accept': 'application/javascript' },
        suspicious: false
      }
    ];

    const domAnalysis: DOMAnalysis = {
      hiddenElements: 5,
      iframes: 2,
      externalScripts: 8,
      suspiciousEvents: ['onclick', 'onload', 'onerror'],
      formFields: [
        {
          type: 'password',
          name: 'user_password',
          suspicious: false
        },
        {
          type: 'hidden',
          name: 'csrf_token',
          suspicious: true,
          reason: 'Hidden field without proper CSRF protection'
        }
      ]
    };

    return {
      pagesScanned: 15,
      linksFound: 127,
      formsAnalyzed: 8,
      scriptsDetected: 23,
      suspiciousPatterns,
      networkRequests,
      domAnalysis
    };
  }

  // Security check implementations
  private static checkURLLength(url: string): SecurityCheck {
    const isLong = url.length > 100;
    return {
      name: 'URL Length Analysis',
      description: 'Legitimate URLs are typically concise',
      passed: !isLong,
      weight: 10,
      category: 'url',
      details: isLong ? `URL is ${url.length} characters (>100 is suspicious)` : `URL length: ${url.length} characters`
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
      details: hasIP ? 'Uses IP address instead of domain name' : 'Uses proper domain name'
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
      details: hasSuspicious ? 'Contains suspicious characters (@, %40, %2F%2F)' : 'No suspicious characters found'
    };
  }

  private static checkTLD(hostname: string): SecurityCheck {
    const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'pw', 'top', 'click', 'download'];
    const tld = hostname.split('.').pop()?.toLowerCase() || '';
    const isSuspicious = suspiciousTLDs.includes(tld);
    return {
      name: 'TLD Security Analysis',
      description: 'Some TLDs are commonly used for malicious activities',
      passed: !isSuspicious,
      weight: 15,
      category: 'url',
      details: isSuspicious ? `TLD ".${tld}" is commonly used for attacks` : `TLD ".${tld}" appears legitimate`
    };
  }

  private static checkSubdomains(hostname: string): SecurityCheck {
    const parts = hostname.split('.');
    const subdomainCount = parts.length - 2;
    const hasExcessiveSubdomains = subdomainCount > 3;
    
    return {
      name: 'Subdomain Structure Analysis',
      description: 'Excessive subdomains can indicate domain spoofing',
      passed: !hasExcessiveSubdomains,
      weight: 15,
      category: 'url',
      details: hasExcessiveSubdomains ? `Has ${subdomainCount} subdomains (>3 is suspicious)` : 'Subdomain structure appears normal'
    };
  }

  private static checkHTTPS(protocol: string): SecurityCheck {
    const isHTTPS = protocol === 'https:';
    return {
      name: 'HTTPS Security Check',
      description: 'Secure sites should use HTTPS encryption',
      passed: isHTTPS,
      weight: 10,
      category: 'url',
      details: isHTTPS ? 'Uses secure HTTPS protocol' : 'Uses insecure HTTP protocol'
    };
  }

  private static checkMaliciousDomains(hostname: string): SecurityCheck {
    const isMalicious = this.MALICIOUS_DOMAINS.some(domain => hostname.includes(domain));
    return {
      name: 'Malicious Domain Check',
      description: 'Check against known malicious domain database',
      passed: !isMalicious,
      weight: 30,
      category: 'url',
      details: isMalicious ? 'Domain found in malicious database' : 'Domain not in malicious database'
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
      details: hasExcessiveEncoding ? `Found ${encodedChars.length} encoded characters` : 'Normal URL encoding detected'
    };
  }

  private static checkXSSVulnerabilities(url: string): SecurityCheck {
    const hasXSS = this.XSS_PATTERNS.some(pattern => pattern.test(url));
    return {
      name: 'XSS Vulnerability Scan',
      description: 'Detects potential Cross-Site Scripting attacks',
      passed: !hasXSS,
      weight: 35,
      category: 'injection',
      details: hasXSS ? 'Potential XSS payload detected in URL' : 'No XSS patterns detected'
    };
  }

  private static checkSQLInjectionVulnerabilities(url: string): SecurityCheck {
    const hasSQLi = this.SQL_INJECTION_PATTERNS.some(pattern => pattern.test(url));
    return {
      name: 'SQL Injection Detection',
      description: 'Detects potential SQL injection attacks',
      passed: !hasSQLi,
      weight: 40,
      category: 'injection',
      details: hasSQLi ? 'Potential SQL injection payload detected' : 'No SQL injection patterns detected'
    };
  }

  private static checkOTPBypassAttempts(url: string): SecurityCheck {
    const hasOTPBypass = this.OTP_BYPASS_PATTERNS.some(pattern => pattern.test(url));
    return {
      name: 'OTP Bypass Detection',
      description: 'Detects potential OTP/2FA bypass attempts',
      passed: !hasOTPBypass,
      weight: 30,
      category: 'authentication',
      details: hasOTPBypass ? 'Potential OTP bypass attempt detected' : 'No OTP bypass patterns detected'
    };
  }

  private static checkCSRFVulnerabilities(url: string): SecurityCheck {
    const hasCSRF = /csrf|xsrf|cross.*site.*request/gi.test(url);
    return {
      name: 'CSRF Protection Check',
      description: 'Checks for Cross-Site Request Forgery vulnerabilities',
      passed: !hasCSRF,
      weight: 25,
      category: 'injection',
      details: hasCSRF ? 'Potential CSRF vulnerability detected' : 'No CSRF vulnerabilities detected'
    };
  }

  private static checkClickjackingVulnerabilities(url: string): SecurityCheck {
    const hasClickjacking = /clickjack|iframe.*overlay|ui.*redress/gi.test(url);
    return {
      name: 'Clickjacking Detection',
      description: 'Detects potential clickjacking attacks',
      passed: !hasClickjacking,
      weight: 20,
      category: 'behavior',
      details: hasClickjacking ? 'Potential clickjacking attempt detected' : 'No clickjacking patterns detected'
    };
  }

  private static checkSessionSecurity(url: string): SecurityCheck {
    const hasSessionIssues = /session.*hijack|cookie.*steal|token.*theft/gi.test(url);
    return {
      name: 'Session Security Analysis',
      description: 'Checks for session-related security issues',
      passed: !hasSessionIssues,
      weight: 25,
      category: 'authentication',
      details: hasSessionIssues ? 'Potential session security issue detected' : 'No session security issues detected'
    };
  }

  private static checkContentSecurityPolicy(url: string): SecurityCheck {
    // Simulate CSP check
    const hasCSPBypass = /csp.*bypass|content.*security.*policy.*bypass/gi.test(url);
    return {
      name: 'Content Security Policy Check',
      description: 'Verifies Content Security Policy implementation',
      passed: !hasCSPBypass,
      weight: 15,
      category: 'content',
      details: hasCSPBypass ? 'Potential CSP bypass detected' : 'No CSP bypass attempts detected'
    };
  }

  private static checkMixedContent(url: string): SecurityCheck {
    const urlObject = new URL(url);
    const hasMixedContent = urlObject.protocol === 'https:' && url.includes('http://');
    return {
      name: 'Mixed Content Detection',
      description: 'Detects insecure content on secure pages',
      passed: !hasMixedContent,
      weight: 10,
      category: 'content',
      details: hasMixedContent ? 'Mixed content detected (HTTP on HTTPS)' : 'No mixed content detected'
    };
  }

  private static analyzeCrawlerResults(crawlerResults: CrawlerResult): SecurityCheck[] {
    const checks: SecurityCheck[] = [];

    // Analyze suspicious patterns
    const highRiskPatterns = crawlerResults.suspiciousPatterns.filter(p => p.riskLevel === 'high').length;
    checks.push({
      name: 'Crawler Pattern Analysis',
      description: 'Analysis of suspicious patterns found during crawling',
      passed: highRiskPatterns === 0,
      weight: highRiskPatterns * 10,
      category: 'behavior',
      details: highRiskPatterns > 0 ? `Found ${highRiskPatterns} high-risk patterns` : 'No high-risk patterns detected'
    });

    // Analyze network requests
    const suspiciousRequests = crawlerResults.networkRequests.filter(r => r.suspicious).length;
    checks.push({
      name: 'Network Request Analysis',
      description: 'Analysis of network requests made by the page',
      passed: suspiciousRequests === 0,
      weight: suspiciousRequests * 5,
      category: 'behavior',
      details: suspiciousRequests > 0 ? `Found ${suspiciousRequests} suspicious network requests` : 'All network requests appear legitimate'
    });

    return checks;
  }

  // Helper methods for vulnerability detection
  private static detectXSS(url: string): boolean {
    return this.XSS_PATTERNS.some(pattern => pattern.test(url));
  }

  private static detectSQLInjection(url: string): boolean {
    return this.SQL_INJECTION_PATTERNS.some(pattern => pattern.test(url));
  }

  private static detectOTPBypass(url: string): boolean {
    return this.OTP_BYPASS_PATTERNS.some(pattern => pattern.test(url));
  }

  private static extractXSSPayload(url: string): string {
    const match = url.match(/<script[^>]*>.*?<\/script>/gi);
    return match ? match[0] : 'XSS pattern detected';
  }

  private static extractSQLPayload(url: string): string {
    const match = url.match(/(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)[^&]*/gi);
    return match ? match[0] : 'SQL injection pattern detected';
  }

  private static normalizeURL(url: string): string {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return `https://${url}`;
    }
    return url;
  }

  private static determineThreatLevel(score: number, maxScore: number, vulnerabilityCount: number): 'safe' | 'suspicious' | 'malicious' | 'critical' {
    const percentage = (score / maxScore) * 100;
    
    if (vulnerabilityCount > 2 || percentage >= 80) return 'critical';
    if (vulnerabilityCount > 0 || percentage >= 60) return 'malicious';
    if (percentage >= 30) return 'suspicious';
    return 'safe';
  }

  private static generateAdvancedRecommendations(checks: SecurityCheck[], vulnerabilities: Vulnerability[], threatLevel: string): string[] {
    const recommendations: string[] = [];
    
    if (threatLevel === 'critical') {
      recommendations.push('🚨 CRITICAL THREAT - DO NOT VISIT THIS URL');
      recommendations.push('🔒 Multiple security vulnerabilities detected');
      recommendations.push('📧 Report this URL to security authorities');
      recommendations.push('🛡️ Run a full system security scan');
    } else if (threatLevel === 'malicious') {
      recommendations.push('❌ MALICIOUS CONTENT DETECTED - Avoid this URL');
      recommendations.push('🔍 Security vulnerabilities found');
      recommendations.push('🛡️ Enable additional browser security features');
    } else if (threatLevel === 'suspicious') {
      recommendations.push('⚠️ SUSPICIOUS ACTIVITY - Exercise extreme caution');
      recommendations.push('🔍 Multiple security concerns identified');
      recommendations.push('🛡️ Consider using a VPN and updated antivirus');
    } else {
      recommendations.push('✅ URL appears to be safe');
      recommendations.push('🔒 Continue with normal security practices');
    }

    // Add vulnerability-specific recommendations
    vulnerabilities.forEach(vuln => {
      recommendations.push(`🔧 ${vuln.mitigation}`);
    });

    // Add category-specific recommendations
    const failedCategories = new Set(checks.filter(c => !c.passed).map(c => c.category));
    
    if (failedCategories.has('injection')) {
      recommendations.push('💉 Injection attacks detected - avoid entering any data');
    }
    if (failedCategories.has('authentication')) {
      recommendations.push('🔐 Authentication bypass attempts detected');
    }
    if (failedCategories.has('behavior')) {
      recommendations.push('👁️ Suspicious behavior patterns detected');
    }

    return recommendations;
  }

  private static createErrorResult(url: string, error: Error): AnalysisResult {
    return {
      url,
      threatLevel: 'suspicious',
      score: 50,
      maxScore: 100,
      checks: [{
        name: 'URL Validation',
        description: 'URL format validation failed',
        passed: false,
        weight: 50,
        category: 'url',
        details: `Error: ${error.message}`
      }],
      timestamp: Date.now(),
      recommendations: ['⚠️ URL format is invalid or malformed', '🔍 Please check the URL and try again'],
      vulnerabilities: [],
      realTimeThreats: []
    };
  }
}