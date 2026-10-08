/**
 * Scan Controller
 * 
 * Handles HTTP requests for:
 * - POST /api/scan   : Run phishing checks, check blocklist, save to DB, return score/verdict/reasons
 * - GET  /api/scans  : Fetch recent scan history
 * - GET  /api/history: Alias for scan history
 * - GET  /api/health : Server and DB health check
 */

const { analyzeUrl, parseUrlDetails } = require('../services/phishingDetector');
const supabaseService = require('../services/supabaseService');

/**
 * Scan a URL for phishing characteristics
 * 
 * Flow:
 * URL → phishing checks → calculate score/verdict/reasons → check blocklist → insert into `scans` → return result
 */
async function scanUrl(req, res) {
  try {
    const rawUrl = req.body?.url || req.body?.link;

    if (!rawUrl || typeof rawUrl !== 'string' || !rawUrl.trim()) {
      return res.status(400).json({
        error: "Missing required 'url' field in request body",
        example: { url: "http://fake-bank.com/login" }
      });
    }

    const trimmedUrl = rawUrl.trim();

    // 1. Extract hostname and root domain for blocklist lookup
    const { hostname, rootDomain } = parseUrlDetails(trimmedUrl);

    // 2. Query blocklist table in Supabase
    const isBlocklisted = await supabaseService.checkBlocklist(hostname, rootDomain);

    // 3. Run security checks and calculate score, verdict & reasons
    const analysis = analyzeUrl(trimmedUrl, isBlocklisted);

    // 4. Save scan result to Supabase `scans` table (reasons as jsonb array)
    const savedRecord = await supabaseService.insertScan({
      url: analysis.url,
      score: analysis.score,
      verdict: analysis.verdict,
      reasons: analysis.reasons
    });

    // 5. Return result matching expected schema
    return res.status(200).json({
      id: savedRecord?.id,
      url: analysis.url,
      score: analysis.score,
      verdict: analysis.verdict,
      reasons: analysis.reasons,
      details: analysis.details,
      created_at: savedRecord?.created_at
    });
  } catch (error) {
    console.error('❌ [scanController] Scan error:', error);
    return res.status(500).json({
      error: 'Internal server error while scanning URL',
      details: error.message
    });
  }
}

/**
 * Retrieve recent scan history
 */
async function getScans(req, res) {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
    const history = await supabaseService.getScanHistory(limit);

    return res.status(200).json(history);
  } catch (error) {
    console.error('❌ [scanController] History fetch error:', error);
    return res.status(500).json({
      error: 'Failed to retrieve scan history',
      details: error.message
    });
  }
}

/**
 * Health check & status endpoint
 */
async function getHealth(req, res) {
  try {
    const dbStatus = supabaseService.getStatus();
    return res.status(200).json({
      status: 'online',
      service: 'PhishGuard API',
      version: '1.0.0',
      database: dbStatus,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    return res.status(500).json({
      status: 'error',
      details: error.message
    });
  }
}

module.exports = {
  scanUrl,
  getScans,
  getHealth
};
