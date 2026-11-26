/**
 * GOTU Intelligence Engine Base Class
 * All intelligence engines implement this interface.
 */

export const EngineStatus = {
  OPERATIONAL:    'operational',      // Working, no key needed or key present
  NOT_CONFIGURED: 'not_configured',  // API key required but not set
  UNSUPPORTED:    'unsupported',      // No reliable method available
  ERROR:          'error',            // Operational but recently errored
  RATE_LIMITED:   'rate_limited',     // Temporarily unavailable
};

export const Confidence = {
  CONFIRMED:   'confirmed',   // API or authoritative source verified
  PROBABLE:    'probable',    // Two+ independent sources consistent
  POSSIBLE:    'possible',    // Single source match
  UNVERIFIED:  'unverified',  // Automated signal only
};

/**
 * @typedef {object} Finding
 * @property {string} type        - e.g. 'profile_found', 'email_breach', 'domain_record'
 * @property {object} data        - normalized finding data
 * @property {string} confidence  - Confidence enum value
 * @property {string} sourceUrl   - Original source URL
 * @property {string} sourceName  - Human-readable source name
 */

/**
 * @typedef {object} Lead
 * @property {string} type        - Indicator type for the new lead
 * @property {string} value       - Value to investigate
 * @property {string} confidence  - Confidence in this lead
 * @property {string} sourceEngine
 */

/**
 * @typedef {object} EngineResult
 * @property {string}    engineId
 * @property {Finding[]} findings
 * @property {Lead[]}    leads
 * @property {string[]}  errors
 * @property {number}    apiCallsUsed
 * @property {string}    timestamp
 */

export class IntelligenceEngine {
  constructor() {
    if (new.target === IntelligenceEngine) {
      throw new Error('IntelligenceEngine is abstract');
    }
  }

  /** @returns {string} Unique engine ID */
  get id() { throw new Error('Not implemented'); }

  /** @returns {string} Human-readable name */
  get name() { throw new Error('Not implemented'); }

  /** @returns {string[]} Supported input types */
  get supportedInputTypes() { return []; }

  /** @returns {string[]} Required API key environment variable names */
  get requiredApiKeys() { return []; }

  /**
   * Check if this engine can run with current configuration.
   * @returns {{ status: string, message: string }}
   */
  getStatus() {
    for (const keyName of this.requiredApiKeys) {
      if (!process.env[keyName]) {
        return {
          status:  EngineStatus.NOT_CONFIGURED,
          message: `Missing required API key: ${keyName}`,
          apiKeyNames: this.requiredApiKeys,
        };
      }
    }
    return { status: EngineStatus.OPERATIONAL, message: 'Ready' };
  }

  /**
   * Execute the engine against an indicator.
   * @param {object} context
   * @param {string} context.indicatorType
   * @param {string} context.indicatorValue
   * @param {string} context.investigationId
   * @returns {Promise<EngineResult>}
   */
  async execute(context) { // eslint-disable-line no-unused-vars
    throw new Error('Not implemented');
  }

  /** Create an empty result object */
  emptyResult() {
    return {
      engineId:     this.id,
      findings:     [],
      leads:        [],
      errors:       [],
      apiCallsUsed: 0,
      timestamp:    new Date().toISOString(),
    };
  }

  /** Utility: build a Finding */
  makeFinding(type, data, confidence, sourceUrl, sourceName) {
    return { type, data, confidence, sourceUrl, sourceName };
  }

  /** Utility: build a Lead */
  makeLead(type, value, confidence = Confidence.POSSIBLE) {
    return { type, value, confidence, sourceEngine: this.id };
  }
}
