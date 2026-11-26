/**
 * GOTU Business Intelligence Engine
 * OpenCorporates API, SEC EDGAR company search.
 */
import https from 'https';
import { IntelligenceEngine, Confidence } from '../base/engine.js';

async function fetchJson(url, headers = {}, timeout = 12000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'GOTU/1.0', 'Accept': 'application/json', ...headers }, timeout }, (res) => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    setTimeout(() => { req.destroy(); reject(new Error('timeout')); }, timeout);
  });
}

export class BusinessEngine extends IntelligenceEngine {
  get id()   { return 'business'; }
  get name() { return 'Business & Corporate Intelligence'; }
  get supportedInputTypes() { return ['organization', 'name', 'domain']; }
  get requiredApiKeys() { return []; }

  async execute(context) {
    const result = this.emptyResult();
    const { indicatorValue: query } = context;
    await Promise.allSettled([
      this._openCorporates(query, result),
      this._secEdgar(query, result),
    ]);
    return result;
  }

  async _openCorporates(query, result) {
    const apiKey = process.env.OPENCORPORATES_API_KEY;
    if (!apiKey) {
      result.findings.push(this.makeFinding(
        'business_source_not_configured',
        { source: 'OpenCorporates', reason: 'Set OPENCORPORATES_API_KEY. Free for open data use. 140+ jurisdictions.', signUpUrl: 'https://opencorporates.com/api_docs' },
        Confidence.CONFIRMED, null, 'OpenCorporates'
      ));
      return;
    }
    try {
      result.apiCallsUsed++;
      const url = `https://api.opencorporates.com/v0.4/companies/search?q=${encodeURIComponent(query)}&api_token=${apiKey}&per_page=10`;
      const res = await fetchJson(url);
      if (res.status !== 200) { result.errors.push(`OpenCorporates: HTTP ${res.status}`); return; }
      const data = JSON.parse(res.body);
      const companies = data.results?.companies ?? [];
      result.findings.push(this.makeFinding(
        'company_search_results',
        { source: 'OpenCorporates', query, totalResults: data.results?.total_count, companies: companies.map(c => c.company).slice(0, 10) },
        Confidence.POSSIBLE, `https://opencorporates.com/companies?q=${encodeURIComponent(query)}`, 'OpenCorporates'
      ));
    } catch (e) {
      result.errors.push(`OpenCorporates: ${e.message}`);
    }
  }

  async _secEdgar(query, result) {
    try {
      result.apiCallsUsed++;
      const url = `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent('"' + query + '"')}&dateRange=custom&startdt=2020-01-01&_source=file_date,display_names,form,adsh&hits.hits._source=display_names,form,file_date,adsh&hits.hits.total.value=true&from=0&hits.hits.highlight.number_of_fragments=3`;
      const res = await fetchJson(url, { 'Accept': 'application/json' });
      if (res.status !== 200) return;
      const data = JSON.parse(res.body);
      const hits = data.hits?.hits ?? [];
      if (hits.length === 0) return;
      result.findings.push(this.makeFinding(
        'sec_edgar_filings',
        { query, totalHits: data.hits?.total?.value, filings: hits.slice(0, 5).map(h => ({ display_names: h._source.display_names, form: h._source.form, file_date: h._source.file_date, adsh: h._source.adsh, url: `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company=${encodeURIComponent(query)}&CIK=&type=&dateb=&owner=include&count=40&search_text=` })) },
        Confidence.CONFIRMED, `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(query)}`, 'SEC EDGAR'
      ));
    } catch (e) {
      result.errors.push(`SEC EDGAR: ${e.message}`);
    }
  }
}
