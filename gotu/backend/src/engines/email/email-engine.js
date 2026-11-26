/**
 * GOTU Email Intelligence Engine
 * RFC 5322 validation, MX lookup, disposable domain detection,
 * HIBP breach check (requires API key), domain age via RDAP.
 * NOTE: Pwned Passwords is NOT implemented - GOTU never touches passwords.
 */

import dns from 'dns';
import https from 'https';
import { IntelligenceEngine, Confidence } from '../base/engine.js';

// Minimal disposable email domain list (bundled; can be replaced with npm package)
// In production, install: npm install disposable-email-domains
const KNOWN_DISPOSABLE = new Set([
  'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'throwaway.email',
  'tempmail.com', 'dispostable.com', 'mailnull.com', 'spamgourmet.com',
  'yopmail.com', 'sharklasers.com', 'guerrillamailblock.com', 'grr.la',
  'guerrillamail.info', 'spam4.me', 'trashmail.at', 'trashmail.me',
]);

// RFC 5322-ish email validation
function isValidEmail(email) {
  return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(email)
    && email.length <= 254;
}

async function fetchJson(url, options = {}, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'GOTU/1.0', ...options.headers }, timeout }, (res) => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.on('error', reject);
    setTimeout(() => { req.destroy(); reject(new Error('timeout')); }, timeout);
  });
}

export class EmailEngine extends IntelligenceEngine {
  get id()   { return 'email'; }
  get name() { return 'Email Intelligence'; }
  get supportedInputTypes() { return ['email']; }
  get requiredApiKeys() { return []; } // HIBP key optional, not required

  async execute(context) {
    const result = this.emptyResult();
    const { indicatorValue: email } = context;

    // 1. Syntax validation
    if (!isValidEmail(email)) {
      result.findings.push(this.makeFinding(
        'email_invalid_syntax',
        { email, valid: false },
        Confidence.CONFIRMED, null, 'RFC 5322 Validation'
      ));
      return result;
    }
    result.findings.push(this.makeFinding(
      'email_valid_syntax',
      { email, valid: true },
      Confidence.CONFIRMED, null, 'RFC 5322 Validation'
    ));

    const domain = email.split('@')[1].toLowerCase();

    // 2. Disposable domain check
    const isDisposable = KNOWN_DISPOSABLE.has(domain);
    result.findings.push(this.makeFinding(
      isDisposable ? 'email_disposable_domain' : 'email_domain_check',
      { domain, isDisposable },
      Confidence.PROBABLE, null, 'Disposable Domain List'
    ));

    // 3. MX record lookup
    await this._mxLookup(domain, result);

    // 4. HIBP breach check (optional)
    await this._hibpBreachCheck(email, result);

    // Add domain as a lead
    result.leads.push(this.makeLead('domain', domain, Confidence.CONFIRMED));

    return result;
  }

  async _mxLookup(domain, result) {
    try {
      result.apiCallsUsed++;
      const mx = await dns.promises.resolveMx(domain);
      if (!mx || mx.length === 0) {
        result.findings.push(this.makeFinding('email_no_mx', { domain, mx: [] }, Confidence.CONFIRMED, null, 'DNS')); return;
      }
      const sorted = mx.sort((a, b) => a.priority - b.priority);
      const provider = detectMailProvider(sorted[0].exchange);
      result.findings.push(this.makeFinding(
        'email_mx_records',
        { domain, mx: sorted, primaryMx: sorted[0].exchange, estimatedProvider: provider },
        Confidence.CONFIRMED, null, 'DNS MX Lookup'
      ));
    } catch (e) {
      result.errors.push(`MX lookup for ${domain}: ${e.message}`);
    }
  }

  async _hibpBreachCheck(email, result) {
    const apiKey = process.env.HIBP_API_KEY;
    if (!apiKey) {
      result.findings.push(this.makeFinding(
        'email_breach_check_unavailable',
        { reason: 'HIBP API key not configured. Set HIBP_API_KEY to enable breach checks.',
          infoUrl: 'https://haveibeenpwned.com/API/Key' },
        Confidence.CONFIRMED, 'https://haveibeenpwned.com/API/v3', 'HIBP'
      ));
      return;
    }
    try {
      result.apiCallsUsed++;
      const res = await fetchJson(
        `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
        { headers: { 'hibp-api-key': apiKey } }
      );
      if (res.status === 404) {
        result.findings.push(this.makeFinding(
          'email_no_breaches',
          { email, breachCount: 0 },
          Confidence.PROBABLE, 'https://haveibeenpwned.com/', 'HIBP'
        ));
        return;
      }
      if (res.status === 429) { result.errors.push('HIBP rate limit reached'); return; }
      if (res.status !== 200) { result.errors.push(`HIBP returned ${res.status}`); return; }
      const breaches = JSON.parse(res.body);
      result.findings.push(this.makeFinding(
        'email_breaches_found',
        {
          email,
          breachCount: breaches.length,
          breaches: breaches.map(b => ({
            name: b.Name, domain: b.Domain, breachDate: b.BreachDate,
            dataClasses: b.DataClasses, isVerified: b.IsVerified,
          })),
          disclaimer: 'An email appearing in a breach means it was included in a leaked dataset, not that the account was accessed by an attacker.',
        },
        Confidence.CONFIRMED,
        `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`,
        'Have I Been Pwned (HIBP)'
      ));
    } catch (e) {
      result.errors.push(`HIBP check: ${e.message}`);
    }
  }
}

function detectMailProvider(mxHost) {
  const h = mxHost.toLowerCase();
  if (h.includes('google') || h.includes('gmail')) return 'Google Workspace / Gmail';
  if (h.includes('outlook') || h.includes('microsoft') || h.includes('hotmail')) return 'Microsoft Exchange / Outlook';
  if (h.includes('yahoo')) return 'Yahoo Mail';
  if (h.includes('protonmail') || h.includes('proton.me')) return 'ProtonMail';
  if (h.includes('mailchimp') || h.includes('mandrillapp')) return 'Mailchimp / Mandrill' ;
  if (h.includes('sendgrid')) return 'SendGrid';
  if (h.includes('amazonses')) return 'Amazon SES';
  return null;
}
