/**
 * PhishGuard Phishing URL Detector Service
 * 
 * Implements the scoring matrix:
 * -------------------------------------------------------------
 * Check                          | Points
 * -------------------------------------------------------------
 * No HTTPS                       |    +20
 * IP address instead of domain   |    +30
 * URL longer than 100 characters |    +10
 * Suspicious keyword present     |    +10
 * More than 2 subdomains         |    +15
 * '@' symbol                     |    +20
 * Domain in blocklist            |    +50
 * -------------------------------------------------------------
 * Verdicts:
 * - Safe: score < 20
 * - Suspicious: 20 <= score < 50
 * - Dangerous: score >= 50 (or blocklisted)
 */

// Common two-part public suffixes for domain parsing
const TWO_PART_TLDS = new Set([
  'co.uk', 'com.au', 'co.in', 'gov.in', 'org.uk', 
  'edu.au', 'ac.uk', 'co.jp', 'net.au', 'org.au'
]);

// Suspicious keywords associated with phishing lures
const SUSPICIOUS_KEYWORDS = [
  'bank',
  'login',
  'verify',
  'account',
  'secure',
  'signin',
  'banking',
  'password',
  'update',
  'confirm',
  'wallet',
  'security',
  'billing',
  'support'
];

/**
 * Validates IPv4 address string
 * @param {string} host 
 * @returns {boolean}
 */
function isIPv4(host) {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  return parts.every(part => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

/**
 * Validates IPv6 address string
 * @param {string} host 
 * @returns {boolean}
 */
function isIPv6(host) {
  const clean = host.replace(/^\[|\]$/g, '');
  return clean.includes(':') && /^[0-9a-fA-F:]+$/.test(clean);
}

/**
 * Extracts normalized hostname and domain from URL string
 * @param {string} rawUrl 
 * @returns {{ hostname: string, rootDomain: string, rawUrl: string }}
 */
function parseUrlDetails(rawUrl) {
  const trimmed = rawUrl.trim();
  let normalizedForParsing = trimmed;

  if (!/^https?:\/\//i.test(normalizedForParsing)) {
    normalizedForParsing = 'http://' + normalizedForParsing;
  }

  let hostname = '';
  try {
    const parsed = new URL(normalizedForParsing);
    hostname = (parsed.hostname || '').toLowerCase();
  } catch {
    const match = trimmed.match(/^(?:https?:\/\/)?([^/:]+)/i);
    hostname = match ? match[1].toLowerCase() : '';
  }

  // Remove port if present in hostname
  hostname = hostname.replace(/:\d+$/, '');

  // Determine root domain (e.g., example.com from sub.example.com)
  const parts = hostname.split('.').filter(Boolean);
  let rootDomain = hostname;

  if (parts.length >= 2 && !isIPv4(hostname) && !isIPv6(hostname)) {
    const lastTwo = parts.slice(-2).join('.');
    if (TWO_PART_TLDS.has(lastTwo) && parts.length >= 3) {
      rootDomain = parts.slice(-3).join('.');
    } else {
      rootDomain = parts.slice(-2).join('.');
    }
  }

  return { hostname, rootDomain, rawUrl: trimmed };
}

/**
 * Counts number of subdomains
 * @param {string} hostname 
 * @returns {number}
 */
function countSubdomains(hostname) {
  if (isIPv4(hostname) || isIPv6(hostname)) return 0;

  const parts = hostname.split('.').filter(Boolean);
  if (parts.length <= 2) return 0;

  const lastTwo = parts.slice(-2).join('.');
  const basePartsCount = TWO_PART_TLDS.has(lastTwo) ? 3 : 2;

  return Math.max(0, parts.length - basePartsCount);
}

/**
 * Analyzes URL against the 7 security criteria and calculates risk score
 * 
 * @param {string} url - Input URL to analyze
 * @param {boolean} isBlocklisted - Whether domain is present in blocklist
 * @returns {{
 *   url: string,
 *   score: number,
 *   verdict: 'Safe' | 'Suspicious' | 'Dangerous',
 *   reasons: string[],
 *   details: object
 * }}
 */
function analyzeUrl(url, isBlocklisted = false) {
  if (!url || typeof url !== 'string') {
    throw new Error('URL must be a non-empty string');
  }

  const { hostname, rootDomain, rawUrl } = parseUrlDetails(url);
  const reasons = [];
  let score = 0;

  // 1. Check: No HTTPS (+20 points)
  const hasHttps = /^https:\/\//i.test(rawUrl);
  if (!hasHttps) {
    score += 20;
    reasons.push("No HTTPS");
  }

  // 2. Check: IP address instead of domain (+30 points)
  const isIp = isIPv4(hostname) || isIPv6(hostname) || /^\d+$/.test(hostname);
  if (isIp) {
    score += 30;
    reasons.push("IP address instead of domain");
  }

  // 3. Check: URL longer than 100 characters (+10 points)
  if (rawUrl.length > 100) {
    score += 10;
    reasons.push("URL longer than 100 characters");
  }

  // 4. Check: Suspicious keyword present (+10 points)
  // Searches full URL (domain, path, and query parameters)
  const lowerUrl = rawUrl.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(keyword => {
    // Check keyword with word boundary or surrounded by standard URL delimiters
    const regex = new RegExp(`(^|[^a-z0-9])${keyword}([^a-z0-9]|$)`, 'i');
    return regex.test(lowerUrl);
  });

  if (matchedKeywords.length > 0) {
    score += 10;
    // Add reason for each matched keyword (e.g. "Suspicious keyword: bank")
    matchedKeywords.forEach(keyword => {
      reasons.push(`Suspicious keyword: ${keyword}`);
    });
  }

  // 5. Check: More than 2 subdomains (+15 points)
  const subdomainsCount = countSubdomains(hostname);
  if (subdomainsCount > 2) {
    score += 15;
    reasons.push("More than 2 subdomains");
  }

  // 6. Check: '@' symbol (+20 points)
  if (rawUrl.includes('@')) {
    score += 20;
    reasons.push("URL contains '@' symbol");
  }

  // 7. Check: Domain in blocklist (+50 points)
  if (isBlocklisted) {
    score += 50;
    reasons.push("Domain found in blocklist");
  }

  // Cap score between 0 and 100
  const finalScore = Math.min(100, Math.max(0, score));

  // Determine Verdict
  let verdict = "Safe";
  if (finalScore >= 50 || isBlocklisted) {
    verdict = "Dangerous";
  } else if (finalScore >= 20) {
    verdict = "Suspicious";
  }

  return {
    url: rawUrl,
    score: finalScore,
    verdict,
    reasons,
    details: {
      hostname,
      rootDomain,
      subdomainsCount,
      isHttps: hasHttps,
      isIpAddress: isIp,
      urlLength: rawUrl.length,
      matchedKeywords,
      isBlocklisted
    }
  };
}

module.exports = {
  analyzeUrl,
  parseUrlDetails,
  countSubdomains,
  isIPv4,
  isIPv6,
  SUSPICIOUS_KEYWORDS
};
