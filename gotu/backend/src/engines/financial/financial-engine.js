/**
 * GOTU Financial Intelligence Engine
 * SEC EDGAR full-text filings, public blockchain transactions.
 * NEVER accesses private banking accounts or infers wallet identity.
 */
import https from 'https';
import { IntelligenceEngine, Confidence } from '../base/engine.js';

const BLOCKCHAIN_DISCLAIMER = 'A public wallet address is a string on a public ledger. GOTU does not infer that any wallet belongs to any specific person unless the analyst provides independently verified documentary evidence. Blockchain data shows transactions only - not identity.';

async function fetchJson(url, timeout = 12000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'GOTU/1.0', 'Accept': 'application/json' }, timeout }, (res) => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    setTimeout(() => { req.destroy(); reject(new Error('timeout')); }, timeout);
  });
}

export class FinancialEngine extends IntelligenceEngine {
  get id()   { return 'financial'; }
  get name() { return 'Public Financial Intelligence'; }
  get supportedInputTypes() { return ['organization', 'other']; } // other = blockchain address
  get requiredApiKeys() { return []; }

  async execute(context) {
    const result = this.emptyResult();
    const { indicatorValue: query, indicatorType } = context;

    // Bitcoin/Ethereum address pattern detection
    const isBtcAddress = /^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$/.test(query);
    const isEthAddress = /^0x[0-9a-fA-F]{40}$/.test(query);

    if (isBtcAddress) {
      await this._bitcoinLookup(query, result);
    } else if (isEthAddress) {
      await this._ethereumLookup(query, result);
    } else {
      await this._secEdgarFilings(query, result);
    }
    return result;
  }

  async _bitcoinLookup(address, result) {
    result.findings.push(this.makeFinding('blockchain_disclaimer', { disclaimer: BLOCKCHAIN_DISCLAIMER }, Confidence.CONFIRMED, null, 'GOTU'));
    try {
      result.apiCallsUsed++;
      const res = await fetchJson(`https://blockchain.info/rawaddr/${address}?limit=10`);
      if (res.status !== 200) { result.errors.push(`Blockchain.info: HTTP ${res.status}`); return; }
      const data = JSON.parse(res.body);
      result.findings.push(this.makeFinding(
        'bitcoin_address_data',
        { address, balance_satoshi: data.final_balance, total_received: data.total_received, total_sent: data.total_sent, n_tx: data.n_tx, recentTx: (data.txs ?? []).slice(0, 5).map(tx => ({ hash: tx.hash, time: new Date(tx.time * 1000).toISOString(), result: tx.result })), disclaimer: BLOCKCHAIN_DISCLAIMER },
        Confidence.CONFIRMED, `https://blockchain.com/explorer/addresses/btc/${address}`, 'Blockchain.info'
      ));
    } catch (e) {
      result.errors.push(`Bitcoin lookup: ${e.message}`);
    }
  }

  async _ethereumLookup(address, result) {
    result.findings.push(this.makeFinding('blockchain_disclaimer', { disclaimer: BLOCKCHAIN_DISCLAIMER }, Confidence.CONFIRMED, null, 'GOTU'));
    try {
      result.apiCallsUsed++;
      const res = await fetchJson(`https://api.blockstream.info/address/${address}`);
      if (res.status === 404) return;
      result.findings.push(this.makeFinding(
        'ethereum_address_data',
        { address, note: 'Ethereum address detected. Use etherscan.io for full transaction history.', explorerUrl: `https://etherscan.io/address/${address}`, disclaimer: BLOCKCHAIN_DISCLAIMER },
        Confidence.CONFIRMED, `https://etherscan.io/address/${address}`, 'Etherscan'
      ));
    } catch (e) {
      result.errors.push(`Ethereum lookup: ${e.message}`);
    }
  }

  async _secEdgarFilings(query, result) {
    try {
      result.apiCallsUsed++;
      const url = `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent('"' + query + '"')}&forms=10-K,10-Q,8-K&dateRange=custom&startdt=2020-01-01`;
      const res = await fetchJson(url);
      if (res.status !== 200) return;
      const data = JSON.parse(res.body);
      const hits = data.hits?.hits ?? [];
      if (hits.length === 0) return;
      result.findings.push(this.makeFinding(
        'sec_financial_filings',
        { query, totalHits: data.hits?.total?.value, filings: hits.slice(0, 5).map(h => ({ display_names: h._source?.display_names, form: h._source?.form, file_date: h._source?.file_date })), source: 'SEC EDGAR public filings. Covers US public company filings only. Does not include private companies or international filings.' },
        Confidence.CONFIRMED, `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(query)}`, 'SEC EDGAR'
      ));
    } catch (e) {
      result.errors.push(`SEC EDGAR financial: ${e.message}`);
    }
  }
}
