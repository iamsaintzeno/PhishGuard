/**
 * Supabase Database Integration Service
 * 
 * Handles interaction with Supabase tables:
 * - `blocklist`: Lookup known malicious domains
 * - `scans`: Insert new scan results & fetch scan history
 * 
 * Features automatic graceful in-memory fallback if Supabase credentials
 * are not yet provided in .env, ensuring zero downtime and instant local testing.
 */

const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY || process.env.SUPABASE_ANON_KEY;

let supabase = null;
let isConfigured = false;

if (SUPABASE_URL && SUPABASE_KEY && !SUPABASE_URL.includes('your-project')) {
  try {
    supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
    isConfigured = true;
    console.log('✅ [Supabase] Connected to live Supabase instance:', SUPABASE_URL);
  } catch (err) {
    console.warn('⚠️ [Supabase] Failed to initialize client. Falling back to local store:', err.message);
  }
} else {
  console.log('ℹ️ [Supabase] SUPABASE_URL or SUPABASE_KEY not set. Using built-in local store fallback.');
  console.log('ℹ️ [Supabase] Add SUPABASE_URL and SUPABASE_KEY to backend/.env to connect live database.');
}

// =========================================================================
// Built-in Mock / Local Fallback Database
// =========================================================================
const mockBlocklist = new Set([
  'fake-bank.com',
  'phish-login.xyz',
  'verify-account-now.com',
  'malicious-portal.org',
  'secure-bank-update.net',
  'paypal-security-center.ru',
  'apple-id-verify.com'
]);

const mockScansHistory = [
  {
    id: 1,
    url: 'http://fake-bank.com/login',
    score: 80,
    verdict: 'Dangerous',
    reasons: [
      'No HTTPS',
      'Suspicious keyword: bank',
      'Suspicious keyword: login',
      'Domain found in blocklist'
    ],
    created_at: new Date(Date.now() - 3600000).toISOString()
  },
  {
    id: 2,
    url: 'https://www.google.com',
    score: 0,
    verdict: 'Safe',
    reasons: [],
    created_at: new Date(Date.now() - 1800000).toISOString()
  }
];

let nextId = 3;

// =========================================================================
// Public Service API
// =========================================================================

/**
 * Check whether a domain (or its root domain) is present in the blocklist
 * 
 * @param {string} domain - Hostname or domain name to check
 * @param {string} rootDomain - Root domain (optional)
 * @returns {Promise<boolean>}
 */
async function checkBlocklist(domain, rootDomain) {
  const normalizedDomain = (domain || '').toLowerCase().trim();
  const normalizedRoot = (rootDomain || '').toLowerCase().trim();

  // If live Supabase client is configured, query the blocklist table
  if (isConfigured && supabase) {
    try {
      // 1. Direct match on domain
      const { data: directMatch, error: directErr } = await supabase
        .from('blocklist')
        .select('domain')
        .ilike('domain', normalizedDomain)
        .limit(1);

      if (!directErr && directMatch && directMatch.length > 0) {
        return true;
      }

      // 2. Check root domain if different
      if (normalizedRoot && normalizedRoot !== normalizedDomain) {
        const { data: rootMatch, error: rootErr } = await supabase
          .from('blocklist')
          .select('domain')
          .ilike('domain', normalizedRoot)
          .limit(1);

        if (!rootErr && rootMatch && rootMatch.length > 0) {
          return true;
        }
      }

      return false;
    } catch (err) {
      console.error('❌ [Supabase] Error during blocklist lookup:', err.message);
      // Fallback to local check on network/query failure
      return mockBlocklist.has(normalizedDomain) || (normalizedRoot && mockBlocklist.has(normalizedRoot));
    }
  }

  // Local fallback lookup
  return mockBlocklist.has(normalizedDomain) || (normalizedRoot && mockBlocklist.has(normalizedRoot));
}

/**
 * Insert a scan result into the `scans` table
 * 
 * @param {object} scanData
 * @param {string} scanData.url
 * @param {number} scanData.score
 * @param {string} scanData.verdict
 * @param {string[]} scanData.reasons - Stored as jsonb in Supabase
 * @returns {Promise<object>} The stored scan record
 */
async function insertScan({ url, score, verdict, reasons }) {
  const scanRecord = {
    url,
    score,
    verdict,
    reasons: Array.isArray(reasons) ? reasons : []
  };

  if (isConfigured && supabase) {
    try {
      const { data, error } = await supabase
        .from('scans')
        .insert([scanRecord])
        .select();

      if (error) {
        console.error('❌ [Supabase] Error inserting scan:', error.message);
        throw error;
      }

      if (data && data.length > 0) {
        return data[0];
      }
    } catch (err) {
      console.warn('⚠️ [Supabase] Insert failed, falling back to local memory:', err.message);
    }
  }

  // Local fallback storage
  const record = {
    id: nextId++,
    ...scanRecord,
    created_at: new Date().toISOString()
  };
  mockScansHistory.unshift(record);
  return record;
}

/**
 * Retrieve latest scan history from `scans` table
 * 
 * @param {number} limit - Maximum number of records to fetch
 * @returns {Promise<object[]>} Array of scan records
 */
async function getScanHistory(limit = 50) {
  if (isConfigured && supabase) {
    try {
      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .order('scanned_at', { ascending: false })
        .limit(limit);

      if (error) {
        console.error('❌ [Supabase] Error fetching scan history:', error.message);
        throw error;
      }

      return data || [];
    } catch (err) {
      console.warn('⚠️ [Supabase] History fetch failed, falling back to local memory:', err.message);
    }
  }

  // Local fallback retrieval
  return mockScansHistory.slice(0, limit);
}

/**
 * Returns connection and status info
 */
function getStatus() {
  return {
    isConfigured,
    provider: isConfigured ? 'supabase_live' : 'in_memory_fallback',
    supabaseUrl: SUPABASE_URL || null,
    totalLocalScans: mockScansHistory.length,
    totalBlocklistedDomains: mockBlocklist.size
  };
}

module.exports = {
  checkBlocklist,
  insertScan,
  getScanHistory,
  getStatus,
  // Exported for testing / seeding
  mockBlocklist,
  mockScansHistory
};
