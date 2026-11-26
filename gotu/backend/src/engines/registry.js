/**
 * GOTU Engine Registry
 * Central registry for all intelligence engines.
 * Engines are lazy-loaded and status-checked before execution.
 */

import { UsernameEngine }  from './username/username-engine.js';
import { DomainEngine }    from './domain/domain-engine.js';
import { EmailEngine }     from './email/email-engine.js';
import { SearchEngine }    from './search/search-engine.js';
import { LegalEngine }     from './legal/legal-engine.js';
import { BusinessEngine }  from './business/business-engine.js';
import { FinancialEngine } from './financial/financial-engine.js';

let _registry = null;

export function getRegistry() {
  if (_registry) return _registry;

  const engines = [
    new UsernameEngine(),
    new DomainEngine(),
    new EmailEngine(),
    new SearchEngine(),
    new LegalEngine(),
    new BusinessEngine(),
    new FinancialEngine(),
  ];

  _registry = {
    _engines: new Map(engines.map(e => [e.id, e])),

    getAll() {
      return [...this._engines.values()];
    },

    getById(id) {
      return this._engines.get(id) ?? null;
    },

    getForInputType(type) {
      return [...this._engines.values()].filter(e =>
        e.supportedInputTypes.includes(type)
      );
    },

    getAllStatuses() {
      return [...this._engines.values()].map(e => ({
        id:     e.id,
        name:   e.name,
        supportedInputTypes: e.supportedInputTypes,
        requiredApiKeys:     e.requiredApiKeys,
        status: e.getStatus(),
      }));
    },
  };

  return _registry;
}
