/**
 * Integration Test for PhishGuard API endpoints
 * Tests POST /api/scan, GET /api/scans, GET /api/history, GET /api/health
 */

const http = require('http');

const BASE_URL = process.env.API_URL || 'http://localhost:5000';

function makeRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const postData = body ? JSON.stringify(body) : null;

    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    if (postData) {
      options.headers['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode,
            data: data ? JSON.parse(data) : null
          });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });

    req.on('error', reject);

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

async function runApiTests() {
  console.log('🚀 Running PhishGuard API Integration Tests against', BASE_URL, '...\n');

  try {
    // 1. Test Health endpoint
    console.log('1️⃣ Testing GET /api/health ...');
    const health = await makeRequest('GET', '/api/health');
    console.log('   Response Status:', health.status);
    console.log('   Response Data:', JSON.stringify(health.data));
    if (health.status !== 200) throw new Error('Health check failed');
    console.log('   ✅ Health check PASSED\n');

    // 2. Test Phishing scan endpoint with prompt example URL
    console.log('2️⃣ Testing POST /api/scan with http://fake-bank.com/login ...');
    const scan1 = await makeRequest('POST', '/api/scan', {
      url: 'http://fake-bank.com/login'
    });
    console.log('   Response Status:', scan1.status);
    console.log('   Response Data:', JSON.stringify(scan1.data, null, 2));
    if (scan1.status !== 200) throw new Error('Scan failed');
    if (scan1.data.verdict !== 'Dangerous') throw new Error('Verdict should be Dangerous');
    console.log('   ✅ Phishing scan PASSED\n');

    // 3. Test Safe URL scan
    console.log('3️⃣ Testing POST /api/scan with https://www.google.com ...');
    const scan2 = await makeRequest('POST', '/api/scan', {
      url: 'https://www.google.com'
    });
    console.log('   Response Status:', scan2.status);
    console.log('   Response Data:', JSON.stringify(scan2.data, null, 2));
    if (scan2.data.verdict !== 'Safe') throw new Error('Verdict should be Safe');
    console.log('   ✅ Safe scan PASSED\n');

    // 4. Test Scan History endpoint
    console.log('4️⃣ Testing GET /api/scans ...');
    const history = await makeRequest('GET', '/api/scans');
    console.log('   Response Status:', history.status);
    console.log('   Total scans retrieved:', Array.isArray(history.data) ? history.data.length : 0);
    console.log('   Latest scan:', JSON.stringify(history.data[0]));
    if (!Array.isArray(history.data) || history.data.length === 0) throw new Error('History should return array');
    console.log('   ✅ History endpoint PASSED\n');

    console.log('🎉 ALL API TESTS PASSED SUCCESSFULLY!');
  } catch (err) {
    console.error('❌ API Test failed:', err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  runApiTests();
}

module.exports = runApiTests;
