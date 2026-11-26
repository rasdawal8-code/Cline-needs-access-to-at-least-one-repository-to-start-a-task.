/**
 * GOTU Legal Intelligence Engine
 * CourtListener (US federal courts), OFAC SDN sanctions list.
 * MANDATORY DISCLAIMER on all findings.
 */
import https from 'https';
import { IntelligenceEngine, Confidence } from '../base/engine.js';

const LEGAL_DISCLAIMER = 'An allegation, charge, indictment, or administrative listing is NOT a conviction or finding of guilt. Names may match different individuals. All results require independent verification before any conclusions are drawn. GOTU does not make findings of criminal liability.';
const OFAC_DISCLAIMER = 'An OFAC SDN listing is an administrative designation by the US Treasury Department. It is NOT a criminal conviction, charge, or finding of guilt. Matching names may refer to different individuals.'

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

export class LegalEngine extends IntelligenceEngine {
  get id()   { return 'legal'; }
  get name() { return 'Legal & Government Intelligence'; }
  get supportedInputTypes() { return ['name', 'organization']; }
  get requiredApiKeys() { return []; }

  async execute(context) {
    const result = this.emptyResult();
    const { indicatorValue: query, indicatorType } = context;

    // Add disclaimer finding at the top of every legal result set
    result.findings.push(this.makeFinding(
      'legal_disclaimer',
      { disclaimer: LEGAL_DISCLAIMER, note: 'Review all results critically. Confirm identity independently before drawing conclusions.' },
      Confidence.CONFIRMED, null, 'GOTU Legal Intelligence'
    ));

    await Promise.allSettled([
      this._courtListenerSearch(query, result),
      this._ofacSearch(query, result),
      this._manualSearchLinks(query, result),
    ]);

    return result;
  }

  async _courtListenerSearch(query, result) {
    try {
      result.apiCallsUsed++;
      const url = `https://www.courtlistener.com/api/rest/v3/search/?q=${encodeURIComponent(query)}&type=o&format=json&page_size=5`;
      const headers = {};
      const clKey = process.env.COURTLISTENER_API_KEY;
      if (clKey) headers['Authorization'] = `Token ${clKey}`;
      const res = await fetchJson(url, headers);
      if (res.status === 429) { result.errors.push('CourtListener rate limited'); return; }
      if (res.status !== 200) { result.errors.push(`CourtListener: HTTP ${res.status}`); return; }
      const data = JSON.parse(res.body);
      const opinions = data.results ?? [];
      result.findings.push(this.makeFinding(
        'court_opinions',
        {
          source: 'CourtListener',
          jurisdiction: 'US Federal Courts (opinions indexed by CourtListener)',
          query,
          totalFound: data.count ?? 0,
          results: opinions.map(o => ({
            caseName: o.caseName,
            court: o.court,
            dateFiled: o.dateFiled,
            url: `https://www.courtlistener.com${o.absolute_url ?? ''}`,
            status: o.status,
            snippet: o.snippet,
          })),
          disclaimer: LEGAL_DISCLAIMER,
          note: 'CourtListener mirrors US federal court opinions via RECAP. It is distinct from PACER and covers published opinions, not all dockets.',
        },
        Confidence.POSSIBLE,
        `https://www.courtlistener.com/?q=${encodeURIComponent(query)}&type=o`,
        'CourtListener'
      ));
    } catch (e) {
      result.errors.push(`CourtListener: ${e.message}`);
    }
  }

  async _ofacSearch(query, result) {
    try {
      // OFAC SDN API - returns sanctions search results
      result.apiCallsUsed++;
      const url = `https://sanctionssearch.ofac.treas.gov/api/search/name/${encodeURIComponent(query)}`;
      const res = await fetchJson(url, { 'Accept': 'application/json' });
      if (res.status === 404 || res.status === 400) {
        result.findings.push(this.makeFinding(
          'ofac_search_result',
          { query, matches: [], matchCount: 0, disclaimer: OFAC_DISCLAIMER },
          Confidence.POSSIBLE, 'https://sanctionssearch.ofac.treas.gov/', 'OFAC SDN'
        ));
        return;
      }
      if (res.status !== 200) { result.errors.push(`OFAC: HTTP ${res.status}`); return; }
      const data = JSON.parse(res.body);
      const matches = Array.isArray(data) ? data : (data.results ?? data.matches ?? []);
      result.findings.push(this.makeFinding(
        matches.length > 0 ? 'ofac_match_found' : 'ofac_no_match',
        { query, matchCount: matches.length, matches: matches.slice(0, 10), disclaimer: OFAC_DISCLAIMER },
        matches.length > 0 ? Confidence.POSSIBLE : Confidence.CONFIRMED,
        'https://sanctionssearch.ofac.treas.gov/', 'OFAC Sanctions'
      ));
    } catch (e) {
      result.errors.push(`OFAC: ${e.message}`);
      // Provide manual link on failure
      result.findings.push(this.makeFinding(
        'ofac_manual_search',
        { query, url: `https://sanctionssearch.ofac.treas.gov/`, disclaimer: OFAC_DISCLAIMER },
        Confidence.UNVERIFIED, 'https://sanctionssearch.ofac.treas.gov/', 'OFAC SDN'
      ));
    }
  }

  _manualSearchLinks(query, result) {
    const encoded = encodeURIComponent(query);
    result.findings.push(this.makeFinding(
      'legal_manual_search_links',
      {
        query,
        links: [
          { label: 'PACER Federal Court Search', url: 'https://pacer.uscourts.gov/', note: 'Requires PACER account. CourtListener mirrors many PACER documents free.' },
          { label: 'Interpol Notices',          url: `https://www.interpol.int/en/How-we-work/Notices/Red-Notices`, note: 'No programmatic API. Manual search required.' },
          { label: 'UK Companies House',         url: `https://find-and-update.company-information.service.gov.uk/search?q=${encoded}`, note: 'Free search for UK company records.' },
          { label: 'EU Official Journal',        url: `https://eur-lex.europa.eu/search.html?qid=&text=${encoded}`, note: 'EU legal publications and sanctions.' },
        ],
        disclaimer: LEGAL_DISCLAIMER,
      },
      Confidence.CONFIRMED, null, 'Manual Legal Research Links'
    ));
  }
}
