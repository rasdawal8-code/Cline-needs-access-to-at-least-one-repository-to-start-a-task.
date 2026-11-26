/**
 * GOTU Search Engine
 * Multi-provider: Google CSE, Brave Search, CommonCrawl CDX.
 * DuckDuckGo Instant Answers API does NOT provide web search results - not used.
 * Dork builder generates formatted query strings for manual analyst use.
 */
import https from 'https';
import { IntelligenceEngine, Confidence, EngineStatus } from '../base/engine.js';

async function fetchJson(url, headers = {}, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const opts = { headers: { 'User-Agent': 'GOTU/1.0', 'Accept': 'application/json', ...headers }, timeout };
    const req = https.get(url, opts, (res) => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    setTimeout(() => { req.destroy(); reject(new Error('timeout')); }, timeout);
  });
}

// Dork query generator - produces formatted strings for analyst manual use
function buildDorkQueries(indicator, type) {
  const queries = [];
  const q = encodeURIComponent;
  if (type === 'username') {
    queries.push({ label: 'Site search', query: `"${indicator}"`, url: `https://www.google.com/search?q=${q('"' + indicator + '"')}`  });
    queries.push({ label: 'Profile mentions', query: `"${indicator}" site:linkedin.com OR site:twitter.com OR site:github.com`, url: `https://www.google.com/search?q=${q('"' + indicator + '" site:linkedin.com OR site:twitter.com OR site:github.com')}` });
    queries.push({ label: 'Email pattern', query: `"@${indicator}" OR "${indicator}@"`, url: `https://www.google.com/search?q=${q('"@' + indicator + '" OR "' + indicator + '@"')}`  });
  } else if (type === 'domain') {
    queries.push({ label: 'Site index', query: `site:${indicator}`, url: `https://www.google.com/search?q=${q('site:' + indicator)}` });
    queries.push({ label: 'Related', query: `related:${indicator}`, url: `https://www.google.com/search?q=${q('related:' + indicator)}` });
    queries.push({ label: 'Cached pages', query: `site:${indicator} -www`, url: `https://www.google.com/search?q=${q('site:' + indicator + ' -www')}` });
    queries.push({ label: 'Exposed files', query: `site:${indicator} filetype:pdf OR filetype:xls OR filetype:doc`, url: `https://www.google.com/search?q=${q('site:' + indicator + ' filetype:pdf OR filetype:xls OR filetype:doc')}` });
  } else if (type === 'email') {
    queries.push({ label: 'Email mentions', query: `"${indicator}"`, url: `https://www.google.com/search?q=${q('"' + indicator + '"')}`  });
    queries.push({ label: 'Breach sites', query: `"${indicator}" site:pastebin.com OR site:paste.ee`, url: `https://www.google.com/search?q=${q('"' + indicator + '" site:pastebin.com OR site:paste.ee')}` });
  } else if (type === 'name') {
    queries.push({ label: 'Name search', query: `"${indicator}"`, url: `https://www.google.com/search?q=${q('"' + indicator + '"')}`  });
    queries.push({ label: 'LinkedIn', query: `"${indicator}" site:linkedin.com`, url: `https://www.google.com/search?q=${q('"' + indicator + '" site:linkedin.com')}` });
    queries.push({ label: 'News', query: `"${indicator}" site:news.google.com OR inurl:news`, url: `https://www.google.com/search?q=${q('"' + indicator + '" inurl:news')}` });
  }
  return queries;
}

export class SearchEngine extends IntelligenceEngine {
  get id()   { return 'search'; }
  get name() { return 'Google Advanced Search & Dorking'; }
  get supportedInputTypes() { return ['username', 'domain', 'email', 'name', 'organization', 'url']; }
  get requiredApiKeys() { return []; } // Keys optional - graceful degradation

  async execute(context) {
    const result = this.emptyResult();
    const { indicatorValue, indicatorType } = context;

    // Always generate dork queries for analyst manual use
    const dorks = buildDorkQueries(indicatorValue, indicatorType);
    result.findings.push(this.makeFinding(
      'dork_queries_generated',
      { indicator: indicatorValue, type: indicatorType, queries: dorks,
        note: 'These are formatted Google dork queries for manual analyst use. Click URLs to search manually.' },
      Confidence.CONFIRMED, null, 'Dork Query Builder'
    ));

    // CommonCrawl CDX API (free - check if domain/URL has been crawled)
    if (['domain', 'url'].includes(indicatorType)) {
      await this._commonCrawlCdx(indicatorValue, indicatorType, result);
    }

    // Google CSE (optional)
    const googleKey = process.env.GOOGLE_CSE_KEY;
    const googleCx  = process.env.GOOGLE_CSE_CX;
    if (googleKey && googleCx) {
      await this._googleCse(indicatorValue, googleKey, googleCx, result);
    } else {
      result.findings.push(this.makeFinding(
        'search_provider_not_configured',
        { provider: 'Google CSE', reason: 'Set GOOGLE_CSE_KEY and GOOGLE_CSE_CX environment variables. Free tier: 100 queries/day.',
          signUpUrl: 'https://programmablesearchengine.google.com/' },
        Confidence.CONFIRMED, null, 'Google Custom Search'
      ));
    }

    // Brave Search (optional)
    const braveKey = process.env.BRAVE_SEARCH_KEY;
    if (braveKey) {
      await this._braveSearch(indicatorValue, braveKey, result);
    } else {
      result.findings.push(this.makeFinding(
        'search_provider_not_configured',
        { provider: 'Brave Search', reason: 'Set BRAVE_SEARCH_KEY. Free credit: ~$5/month (~1000 requests). $5.00/1000 above that.',
          pricingUrl: 'https://api-dashboard.search.brave.com/documentation/pricing', signUpUrl: 'https://api.search.brave.com/' },
        Confidence.CONFIRMED, null, 'Brave Search'
      ));
    }

    return result;
  }

  async _commonCrawlCdx(indicator, type, result) {
    try {
      result.apiCallsUsed++;
      const q = type === 'url' ? indicator : `*.${indicator}`;
      const url = `https://index.commoncrawl.org/CC-MAIN-2025-21-index?url=${encodeURIComponent(q)}&output=json&limit=5`;
      const res = await fetchJson(url, {}, 15000);
      if (res.status !== 200) return;
      const lines = res.body.trim().split('\n').filter(Boolean).slice(0, 5);
      const records = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      if (records.length === 0) return;
      result.findings.push(this.makeFinding(
        'commoncrawl_presence',
        { indicator, recordCount: records.length, mostRecent: records[0] },
        Confidence.CONFIRMED, `https://index.commoncrawl.org/`, 'Common Crawl CDX'
      ));
    } catch (e) {
      result.errors.push(`CommonCrawl CDX: ${e.message}`);
    }
  }

  async _googleCse(query, key, cx, result) {
    try {
      result.apiCallsUsed++;
      const url = `https://www.googleapis.com/customsearch/v1?key=${key}&cx=${cx}&q=${encodeURIComponent(query)}&num=10`;
      const res = await fetchJson(url);
      if (res.status === 429) { result.errors.push('Google CSE rate limit reached'); return; }
      if (res.status !== 200) { result.errors.push(`Google CSE: HTTP ${res.status}`); return; }
      const data = JSON.parse(res.body);
      const items = data.items ?? [];
      result.findings.push(this.makeFinding(
        'search_results',
        { provider: 'Google CSE', query, totalResults: data.searchInformation?.totalResults ?? 'unknown',
          results: items.map(i => ({ title: i.title, url: i.link, snippet: i.snippet })),
          limitation: 'Google CSE searches a custom engine index, not full Google Search. Dork operators have limited support.' },
        Confidence.POSSIBLE, null, 'Google Custom Search'
      ));
      items.forEach(i => {
        try { const d = new URL(i.link).hostname; result.leads.push(this.makeLead('domain', d, Confidence.POSSIBLE)); } catch {}
      });
    } catch (e) {
      result.errors.push(`Google CSE: ${e.message}`);
    }
  }

  async _braveSearch(query, key, result) {
    try {
      result.apiCallsUsed++;
      const url = `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=10`;
      const res = await fetchJson(url, { 'Accept': 'application/json', 'Accept-Encoding': 'gzip', 'X-Subscription-Token': key });
      if (res.status === 429) { result.errors.push('Brave Search rate limited'); return; }
      if (res.status !== 200) { result.errors.push(`Brave Search: HTTP ${res.status}`); return; }
      const data = JSON.parse(res.body);
      const items = data.web?.results ?? [];
      result.findings.push(this.makeFinding(
        'search_results',
        { provider: 'Brave Search', query,
          results: items.map(i => ({ title: i.title, url: i.url, snippet: i.description })) },
        Confidence.POSSIBLE, null, 'Brave Search'
      ));
      items.forEach(i => {
        try { const d = new URL(i.url).hostname; result.leads.push(this.makeLead('domain', d, Confidence.POSSIBLE)); } catch {}
      });
    } catch (e) {
      result.errors.push(`Brave Search: ${e.message}`);
    }
  }
}
