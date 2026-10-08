/**
 * Unit Test for Phishing URL Detector scoring logic and checks
 */

const { analyzeUrl } = require('../src/services/phishingDetector');

function runTests() {
  console.log('🧪 Starting PhishGuard Scoring & Detection Unit Tests...\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, testName, details = '') {
    if (condition) {
      console.log(`  ✅ PASS: ${testName}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${testName} ${details ? `(${details})` : ''}`);
      failed++;
    }
  }

  // 1. Test clean legitimate HTTPS URL
  const safeRes = analyzeUrl('https://www.google.com', false);
  assert(safeRes.score === 0, 'Safe URL gets score 0', `got ${safeRes.score}`);
  assert(safeRes.verdict === 'Safe', 'Safe URL gets Safe verdict');
  assert(safeRes.reasons.length === 0, 'Safe URL has no triggered reasons');

  // 2. Test No HTTPS (+20 points)
  const noHttpsRes = analyzeUrl('http://example.com', false);
  assert(noHttpsRes.score === 20, 'No HTTPS adds 20 points', `got ${noHttpsRes.score}`);
  assert(noHttpsRes.reasons.includes('No HTTPS'), 'Reason contains "No HTTPS"');
  assert(noHttpsRes.verdict === 'Suspicious', 'Score 20 gives Suspicious verdict');

  // 3. Test IP Address instead of domain (+30 points)
  const ipRes = analyzeUrl('https://192.168.1.1/dashboard', false);
  assert(ipRes.score === 30, 'IP address adds 30 points', `got ${ipRes.score}`);
  assert(ipRes.reasons.includes('IP address instead of domain'), 'Reason contains "IP address instead of domain"');

  // 4. Test URL length > 100 characters (+10 points)
  const longUrl = 'https://example.com/' + 'a'.repeat(90);
  const longRes = analyzeUrl(longUrl, false);
  assert(longRes.score === 10, 'Long URL (>100 chars) adds 10 points', `got ${longRes.score}`);
  assert(longRes.reasons.includes('URL longer than 100 characters'), 'Reason contains "URL longer than 100 characters"');

  // 5. Test Suspicious keyword present (+10 points)
  const kwRes = analyzeUrl('https://myportal.com/login', false);
  assert(kwRes.score === 10, 'Suspicious keyword adds 10 points', `got ${kwRes.score}`);
  assert(kwRes.reasons.some(r => r.includes('login')), 'Reason contains keyword login');

  // 6. Test More than 2 subdomains (+15 points)
  const subRes = analyzeUrl('https://alpha.beta.gamma.example.com', false);
  assert(subRes.score === 15, 'More than 2 subdomains adds 15 points', `got ${subRes.score}`);
  assert(subRes.reasons.includes('More than 2 subdomains'), 'Reason contains "More than 2 subdomains"');

  // 7. Test '@' symbol (+20 points)
  const atRes = analyzeUrl('https://legit.com@attacker.com', false);
  assert(atRes.score === 20, '@ symbol adds 20 points', `got ${atRes.score}`);
  assert(atRes.reasons.includes("URL contains '@' symbol"), "Reason contains @ symbol");

  // 8. Test Domain in blocklist (+50 points)
  const blockRes = analyzeUrl('https://known-bad.com', true);
  assert(blockRes.score === 50, 'Blocklisted domain adds 50 points', `got ${blockRes.score}`);
  assert(blockRes.reasons.includes('Domain found in blocklist'), 'Reason contains "Domain found in blocklist"');
  assert(blockRes.verdict === 'Dangerous', 'Blocklist gives Dangerous verdict');

  // 9. Test Prompt Example: http://fake-bank.com/login with blocklist
  const exampleRes = analyzeUrl('http://fake-bank.com/login', true);
  // No HTTPS (+20) + Keyword bank/login (+10) + Blocklist (+50) = 80
  assert(exampleRes.reasons.includes('No HTTPS'), 'Example has "No HTTPS"');
  assert(exampleRes.reasons.some(r => r.includes('bank')), 'Example has "bank" keyword');
  assert(exampleRes.reasons.includes('Domain found in blocklist'), 'Example has "Domain found in blocklist"');
  assert(exampleRes.verdict === 'Dangerous', 'Example verdict is Dangerous');

  console.log(`\n==========================================`);
  console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  console.log(`==========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  runTests();
}

module.exports = runTests;
