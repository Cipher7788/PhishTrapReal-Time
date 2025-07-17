import { AnalysisResult, SecurityCheck } from '../types';

export class URLAnalyzer {
  private static readonly SUSPICIOUS_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'pw', 'top', 'click', 'download', 'stream',
    'xyz', 'science', 'work', 'party', 'review', 'country', 'kim'
  ];

  private static readonly TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
    'youtube.com', 'twitter.com', 'linkedin.com', 'instagram.com'
  ];

  private static readonly SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'security', 'update', 'confirm',
    'suspended', 'locked', 'expired', 'urgent', 'immediate', 'action'
  ];

  public static analyzeURL(url: string): AnalysisResult {
    try {
      // Normalize URL
      const normalizedUrl = this.normalizeURL(url);
      const urlObject = new URL(normalizedUrl);
      
      const checks: SecurityCheck[] = [
        this.checkURLLength(normalizedUrl),
        this.checkIPAddress(urlObject.hostname),
        this.checkSuspiciousCharacters(normalizedUrl),
        this.checkTLD(urlObject.hostname),
        this.checkSubdomains(urlObject.hostname),
        this.checkSuspiciousKeywords(normalizedUrl),
        this.checkURLStructure(normalizedUrl),
        this.checkTrustedDomain(urlObject.hostname),
        this.checkHTTPS(urlObject.protocol),
        this.checkSuspiciousPath(urlObject.pathname + urlObject.search)
      ];

      const score = checks.reduce((sum, check) => {
        return sum + (check.passed ? 0 : check.weight);
      }, 0);

      const maxScore = checks.reduce((sum, check) => sum + check.weight, 0);
      const threatLevel = this.determineThreatLevel(score, maxScore);
      const recommendations = this.generateRecommendations(checks, threatLevel);

      return {
        url: normalizedUrl,
        threatLevel,
        score,
        maxScore,
        checks,
        timestamp: Date.now(),
        recommendations
      };
    } catch (error) {
      return this.createErrorResult(url, error as Error);
    }
  }

  private static normalizeURL(url: string): string {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return `https://${url}`;
    }
    return url;
  }

  private static checkURLLength(url: string): SecurityCheck {
    const isLong = url.length > 100;
    return {
      name: 'URL Length',
      description: 'Legitimate URLs are typically concise',
      passed: !isLong,
      weight: 10,
      details: isLong ? `URL is ${url.length} characters (>100 is suspicious)` : `URL length: ${url.length} characters`
    };
  }

  private static checkIPAddress(hostname: string): SecurityCheck {
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const hasIP = ipPattern.test(hostname);
    return {
      name: 'IP Address Usage',
      description: 'Legitimate sites use domain names, not IP addresses',
      passed: !hasIP,
      weight: 25,
      details: hasIP ? 'Uses IP address instead of domain name' : 'Uses proper domain name'
    };
  }

  private static checkSuspiciousCharacters(url: string): SecurityCheck {
    const suspiciousChars = /@|%40/;
    const hasSuspicious = suspiciousChars.test(url);
    return {
      name: 'Suspicious Characters',
      description: 'URLs with @ symbols often redirect to malicious sites',
      passed: !hasSuspicious,
      weight: 20,
      details: hasSuspicious ? 'Contains suspicious characters (@, %40)' : 'No suspicious characters found'
    };
  }

  private static checkTLD(hostname: string): SecurityCheck {
    const tld = hostname.split('.').pop()?.toLowerCase() || '';
    const isSuspicious = this.SUSPICIOUS_TLDS.includes(tld);
    return {
      name: 'Top-Level Domain',
      description: 'Some TLDs are commonly used for phishing',
      passed: !isSuspicious,
      weight: 15,
      details: isSuspicious ? `TLD ".${tld}" is commonly used for phishing` : `TLD ".${tld}" appears legitimate`
    };
  }

  private static checkSubdomains(hostname: string): SecurityCheck {
    const parts = hostname.split('.');
    const subdomainCount = parts.length - 2;
    const hasExcessiveSubdomains = subdomainCount > 2;
    
    // Check for trusted domain abuse
    const domainAbuse = this.TRUSTED_DOMAINS.some(trusted => 
      hostname.includes(trusted) && !hostname.endsWith(trusted)
    );

    return {
      name: 'Subdomain Analysis',
      description: 'Excessive subdomains or domain spoofing can indicate phishing',
      passed: !hasExcessiveSubdomains && !domainAbuse,
      weight: domainAbuse ? 30 : 10,
      details: domainAbuse ? 'Appears to abuse trusted domain name' : 
               hasExcessiveSubdomains ? `Has ${subdomainCount} subdomains (>2 is suspicious)` : 
               'Subdomain structure appears normal'
    };
  }

  private static checkSuspiciousKeywords(url: string): SecurityCheck {
    const lowerUrl = url.toLowerCase();
    const foundKeywords = this.SUSPICIOUS_KEYWORDS.filter(keyword => 
      lowerUrl.includes(keyword)
    );
    
    const hasSuspiciousKeywords = foundKeywords.length > 0;
    return {
      name: 'Suspicious Keywords',
      description: 'Phishing URLs often contain urgent or security-related terms',
      passed: !hasSuspiciousKeywords,
      weight: foundKeywords.length * 5,
      details: hasSuspiciousKeywords ? 
               `Contains suspicious keywords: ${foundKeywords.join(', ')}` : 
               'No suspicious keywords found'
    };
  }

  private static checkURLStructure(url: string): SecurityCheck {
    const hasMultipleSubdomains = (url.match(/\./g) || []).length > 3;
    const hasLongPath = url.split('/').length > 6;
    const hasRandomString = /[a-zA-Z0-9]{20,}/.test(url);
    
    const structureIssues = [hasMultipleSubdomains, hasLongPath, hasRandomString].filter(Boolean).length;
    
    return {
      name: 'URL Structure',
      description: 'Legitimate URLs typically have clean, organized structure',
      passed: structureIssues === 0,
      weight: structureIssues * 8,
      details: structureIssues > 0 ? 
               'URL structure appears complex or randomized' : 
               'URL structure appears clean'
    };
  }

  private static checkTrustedDomain(hostname: string): SecurityCheck {
    const isTrusted = this.TRUSTED_DOMAINS.some(trusted => 
      hostname === trusted || hostname.endsWith(`.${trusted}`)
    );
    
    return {
      name: 'Domain Reputation',
      description: 'Known trusted domains are generally safe',
      passed: true, // This is a bonus check, doesn't penalize
      weight: 0,
      details: isTrusted ? 'Domain is on trusted list' : 'Domain not on trusted list (not necessarily bad)'
    };
  }

  private static checkHTTPS(protocol: string): SecurityCheck {
    const isHTTPS = protocol === 'https:';
    return {
      name: 'HTTPS Usage',
      description: 'Secure sites should use HTTPS encryption',
      passed: isHTTPS,
      weight: 5,
      details: isHTTPS ? 'Uses secure HTTPS protocol' : 'Uses insecure HTTP protocol'
    };
  }

  private static checkSuspiciousPath(path: string): SecurityCheck {
    const hasPhishingPath = /\/(login|signin|verify|account|security|update|confirm)/i.test(path);
    const hasLongQuery = path.includes('?') && path.length > 100;
    
    return {
      name: 'Path Analysis',
      description: 'Suspicious paths often indicate phishing attempts',
      passed: !hasPhishingPath && !hasLongQuery,
      weight: hasPhishingPath ? 15 : (hasLongQuery ? 10 : 0),
      details: hasPhishingPath ? 'Path contains suspicious login/security terms' :
               hasLongQuery ? 'Query string is unusually long' :
               'Path appears normal'
    };
  }

  private static determineThreatLevel(score: number, maxScore: number): 'safe' | 'suspicious' | 'malicious' {
    const percentage = (score / maxScore) * 100;
    
    if (percentage >= 60) return 'malicious';
    if (percentage >= 30) return 'suspicious';
    return 'safe';
  }

  private static generateRecommendations(checks: SecurityCheck[], threatLevel: string): string[] {
    const recommendations: string[] = [];
    
    if (threatLevel === 'malicious') {
      recommendations.push('❌ DO NOT visit this URL - it appears to be malicious');
      recommendations.push('🔒 Verify the URL directly with the official website');
      recommendations.push('📧 If received via email, report as phishing');
    } else if (threatLevel === 'suspicious') {
      recommendations.push('⚠️ Exercise caution when visiting this URL');
      recommendations.push('🔍 Double-check the domain spelling and legitimacy');
      recommendations.push('🛡️ Avoid entering sensitive information');
    } else {
      recommendations.push('✅ URL appears to be safe');
      recommendations.push('🔒 Always verify HTTPS for sensitive transactions');
    }

    // Add specific recommendations based on failed checks
    const failedChecks = checks.filter(check => !check.passed && check.weight > 0);
    failedChecks.forEach(check => {
      if (check.name === 'IP Address Usage') {
        recommendations.push('🌐 Legitimate sites use domain names, not IP addresses');
      } else if (check.name === 'Suspicious Characters') {
        recommendations.push('🚨 Be wary of URLs containing @ symbols - they often redirect');
      } else if (check.name === 'Subdomain Analysis') {
        recommendations.push('🔍 Check if the domain is trying to impersonate a trusted site');
      }
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
        name: 'URL Validation',
        description: 'URL format validation failed',
        passed: false,
        weight: 50,
        details: `Error: ${error.message}`
      }],
      timestamp: Date.now(),
      recommendations: ['⚠️ URL format is invalid or malformed', '🔍 Please check the URL and try again']
    };
  }
}