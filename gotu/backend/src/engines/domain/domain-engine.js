/**
 * GOTU Domain & Infrastructure Intelligence Engine
 * WHOIS/RDAP, DNS, Certificate Transparency, security headers.
 */

import dns from 'dns';
import https from 'https';
import http from 'http';
import { IntelligenceEngine, Confidence } from '../base/engine.js';

async function fetchJson(url, timeout = 8000) {
  return new Promise((resolve, reject) => {
    const transport = url.startsWith('https') ? https : http;
    const req = transport.get(url, { headers: { 'User-Agent': 'GOTU/1.0', 'Accept': 'application/json' }, timeout }, (res) => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    setTimeout(() => { req.destroy(); reject(new Error('timeout')); }, timeout);
  });
}

export class DomainEngine extends IntelligenceEngine {
  get id()   { return 'domain'; }
  get name() { return 'Domain & Infrastructure Intelligence'; }
  get supportedInputTypes() { return ['domain', 'url']; }
  get requiredApiKeys() { return []; }

  async execute(context) {
    const result = this.emptyResult();
    let { indicatorValue } = context;
    // Normalize: strip scheme
    try {
      if (indicatorValue.includes('://')) indicatorValue = new URL(indicatorValue).hostname;
    } catch {}
    const domain = indicatorValue.toLowerCase().trim();

    await Promise.allSettled([
      this._dnsLookup(domain, result),
      this._rdap(domain, result),
      this._crtSh(domain, result),
    ]);

    return result;
  }

  async _dnsLookup(domain, result) {
    const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA'];
    for (const type of types) {
      try {
        result.apiCallsUsed++;
        let records;
        if (type === 'A')    records = await dns.promises.resolve4(domain).catch(() => []);
        else if (type === 'AAAA') records = await dns.promises.resolve6(domain).catch(() => []);
        else if (type === 'MX')   records = await dns.promises.resolveMx(domain).catch(() => []);
        else if (type === 'TXT')  records = await dns.promises.resolveTxt(domain).catch(() => []);
        else if (type === 'NS')   records = await dns.promises.resolveNs(domain).catch(() => []);
        else if (type === 'SOA')  records = await dns.promises.resolveSoa(domain).catch(() => null);
        if (!records || (Array.isArray(records) && records.length === 0)) continue;
        result.findings.push(this.makeFinding(
          `dns_${type.toLowerCase()}_record`,
          { domain, recordType: type, records },
          Confidence.CONFIRMED, null, 'DNS')
        );
      } catch (e) {
        result.errors.push(`DNS ${type} for ${domain}: ${e.message}`);
      }
    }
  }

  async _rdap(domain, result) {
    try {
      result.apiCallsUsed++;
      const tld = domain.split('.').pop();
      // Use IANA RDAP bootstrap to find the right RDAP server
      const bootstrapRes = await fetchJson('https://data.iana.org/rdap/dns.json');
      if (bootstrapRes.status !== 200) {
        result.errors.push('RDAP bootstrap unavailable');
        return;
      }
      const bootstrap = JSON.parse(bootstrapRes.body);
      let rdapBase = null;
      for (const service of bootstrap.services) {
        if (service[0].includes(tld)) { rdapBase = service[1][0]; break; }
      }
      if (!rdapBase) {
        result.findings.push(this.makeFinding('whois_no_rdap', { domain, note: 'No RDAP server found for TLD: ' + tld }, Confidence.CONFIRMED, null, 'RDAP'));
        return;
      }
      const rdapUrl = `${rdapBase.replace(/\/$/, '')}/domain/${domain}`;
      result.apiCallsUsed++;
      const rdapRes = await fetchJson(rdapUrl);
      if (rdapRes.status !== 200) return;
      const rdap = JSON.parse(rdapRes.body);
      const registrant = rdap.entities?.find(e => e.roles?.includes('registrant'));
      const registrar  = rdap.entities?.find(e => e.roles?.includes('registrar'));
      const events = rdap.events ?? [];
      const registered = events.find(e => e.eventAction === 'registration')?.eventDate;
      const expires     = events.find(e => e.eventAction === 'expiration')?.eventDate;
      const updated     = events.find(e => e.eventAction === 'last changed')?.eventDate;
      result.findings.push(this.makeFinding(
        'whois_rdap',
        {
          domain,
          registrar:    registrar?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] ?? null,
          registrant:   registrant?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] ?? 'REDACTED',
          registered,
          expires,
          updated,
          status:       rdap.status ?? [],
          nameservers:  rdap.nameservers?.map(n => n.ldhName) ?? [],
          rdapUrl,
        },
        Confidence.CONFIRMED, rdapUrl, 'RDAP'
      ));
    } catch (e) {
      result.errors.push(`RDAP for ${domain}: ${e.message}`);
    }
  }

  async _crtSh(domain, result) {
    try {
      result.apiCallsUsed++;
      // Query crt.sh for certificates — includes subdomains via SANs
      const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
      const res = await fetchJson(url, 15000);
      if (res.status !== 200) return;
      const certs = JSON.parse(res.body);
      if (!Array.isArray(certs)) return;
      // Deduplicate subdomains from SANs
      const subdomains = new Set();
      for (const cert of certs) {
        const names = cert.name_value?.split('\n') ?? [];
        for (const name of names) {
          const n = name.trim().replace(/^\*\./, '');
          if (n.endsWith(domain) && n !== domain) subdomains.add(n);
        }
      }
      result.findings.push(this.makeFinding(
        'certificate_transparency',
        {
          domain,
          certificateCount: certs.length,
          subdomains: [...subdomains].sort(),
          mostRecent: certs[0] ? { notBefore: certs[0].not_before, notAfter: certs[0].not_after, issuer: certs[0].issuer_name } : null,
        },
        Confidence.CONFIRMED,
        `https://crt.sh/?q=%.${domain}`,
        'Certificate Transparency (crt.sh)'
      ));
      // Add discovered subdomains as leads
      for (const sub of subdomains) {
        result.leads.push(this.makeLead('domain', sub, Confidence.POSSIBLE));
      }
    } catch (e) {
      result.errors.push(`crt.sh for ${domain}: ${e.message}`);
    }
  }
}
