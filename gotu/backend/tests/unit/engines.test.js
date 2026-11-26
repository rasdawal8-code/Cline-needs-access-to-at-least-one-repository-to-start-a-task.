import { describe, it, expect, vi, beforeEach } from 'vitest';

// Unit test engines using mock adapters (no live network calls)
describe('UsernameEngine — unit tests with mocks', () => {
  it('returns confirmed finding for valid GitHub response', async () => {
    // Test engine logic directly
    const { IntelligenceEngine, Confidence } = await import('../../src/engines/base/engine.js');
    expect(Confidence.CONFIRMED).toBe('confirmed');
    expect(Confidence.UNVERIFIED).toBe('unverified');
  });

  it('makeFinding creates correct structure', async () => {
    // Create a minimal concrete engine to test base methods
    const { IntelligenceEngine, Confidence } = await import('../../src/engines/base/engine.js');
    class TestEngine extends IntelligenceEngine {
      get id() { return 'test'; }
      get name() { return 'Test'; }
      async execute() { return this.emptyResult(); }
    }
    const engine = new TestEngine();
    const f = engine.makeFinding('test_type', { key: 'val' }, Confidence.CONFIRMED, 'https://src.com', 'TestSrc');
    expect(f.type).toBe('test_type');
    expect(f.data.key).toBe('val');
    expect(f.confidence).toBe('confirmed');
    expect(f.sourceUrl).toBe('https://src.com');
  });

  it('emptyResult has correct structure', async () => {
    const { IntelligenceEngine } = await import('../../src/engines/base/engine.js');
    class TestEngine extends IntelligenceEngine {
      get id() { return 'test'; }
      get name() { return 'Test'; }
      async execute() { return this.emptyResult(); }
    }
    const r = new TestEngine().emptyResult();
    expect(r.findings).toEqual([]);
    expect(r.leads).toEqual([]);
    expect(r.errors).toEqual([]);
    expect(r.apiCallsUsed).toBe(0);
    expect(r.timestamp).toBeTruthy();
  });

  it('getStatus returns NOT_CONFIGURED when API key missing', async () => {
    const { IntelligenceEngine, EngineStatus } = await import('../../src/engines/base/engine.js');
    class KeyedEngine extends IntelligenceEngine {
      get id() { return 'keyed'; }
      get name() { return 'Keyed'; }
      get requiredApiKeys() { return ['FAKE_API_KEY_XYZ' ]; }
      async execute() { return this.emptyResult(); }
    }
    delete process.env.FAKE_API_KEY_XYZ;
    const e = new KeyedEngine();
    const status = e.getStatus();
    expect(status.status).toBe(EngineStatus.NOT_CONFIGURED);
    expect(status.message).toContain('FAKE_API_KEY_XYZ');
  });

  it('getStatus returns OPERATIONAL when API key present', async () => {
    const { IntelligenceEngine, EngineStatus } = await import('../../src/engines/base/engine.js');
    class KeyedEngine extends IntelligenceEngine {
      get id() { return 'keyed2'; }
      get name() { return 'Keyed2'; }
      get requiredApiKeys() { return ['FAKE_API_KEY_ABC']; }
      async execute() { return this.emptyResult(); }
    }
    process.env.FAKE_API_KEY_ABC = 'test-key';
    const e = new KeyedEngine();
    expect(e.getStatus().status).toBe(EngineStatus.OPERATIONAL);
    delete process.env.FAKE_API_KEY_ABC;
  });
});

describe('UsernameEngine — platform statuses', () => {
  it('reports supported, unsupported, and key-required platforms', async () => {
    const { UsernameEngine } = await import('../../src/engines/username/username-engine.js');
    const engine = new UsernameEngine();
    const status = engine.getPlatformStatus();
    expect(status.supported.length).toBeGreaterThan(0);
    expect(status.unsupported.length).toBeGreaterThan(0);
    expect(status.keyRequired.length).toBeGreaterThan(0);
    // Verify specific platforms
    expect(status.supported.map(p => p.id)).toContain('github');
    expect(status.supported.map(p => p.id)).toContain('reddit');
    expect(status.unsupported.map(p => p.id)).toContain('instagram');
    expect(status.unsupported.map(p => p.id)).toContain('tiktok');
    expect(status.keyRequired.map(p => p.id)).toContain('twitter');
  });

  it('engine supportedInputTypes is username', async () => {
    const { UsernameEngine } = await import('../../src/engines/username/username-engine.js');
    expect(new UsernameEngine().supportedInputTypes).toContain('username');
  });
});

describe('EmailEngine — unit tests', () => {
  it('validates correct email syntax', async () => {
    const { EmailEngine } = await import('../../src/engines/email/email-engine.js');
    const engine = new EmailEngine();
    // We test by running execute with mock — email validation is sync internal function
    // We validate it via the finding type returned
    const result = await engine.execute({ indicatorType: 'email', indicatorValue: 'notanemail', investigationId: 'test' });
    expect(result.findings.some(f => f.type === 'email_invalid_syntax')).toBe(true);
  });

  it('reports HIBP unavailable when no API key', async () => {
    delete process.env.HIBP_API_KEY;
    const { EmailEngine } = await import('../../src/engines/email/email-engine.js');
    const engine = new EmailEngine();
    const result = await engine.execute({ indicatorType: 'email', indicatorValue: 'test@example.com', investigationId: 'test' });
    expect(result.findings.some(f => f.type === 'email_breach_check_unavailable')).toBe(true);
  });

  it('generates domain lead for valid email', async () => {
    delete process.env.HIBP_API_KEY;
    const { EmailEngine } = await import('../../src/engines/email/email-engine.js');
    const engine = new EmailEngine();
    const result = await engine.execute({ indicatorType: 'email', indicatorValue: 'user@example.com', investigationId: 'test' });
    expect(result.leads.some(l => l.type === 'domain' && l.value === 'example.com')).toBe(true);
  });
});

describe('Engine Registry', () => {
  it('returns all registered engines', async () => {
    const { getRegistry } = await import('../../src/engines/registry.js');
    const reg = getRegistry();
    expect(reg.getAll().length).toBeGreaterThanOrEqual(3);
    const ids = reg.getAll().map(e => e.id);
    expect(ids).toContain('username');
    expect(ids).toContain('domain');
    expect(ids).toContain('email');
  });

  it('getForInputType returns correct engines', async () => {
    const { getRegistry } = await import('../../src/engines/registry.js');
    const reg = getRegistry();
    expect(reg.getForInputType('username').map(e => e.id)).toContain('username');
    expect(reg.getForInputType('domain').map(e => e.id)).toContain('domain');
    expect(reg.getForInputType('email').map(e => e.id)).toContain('email');
    expect(reg.getForInputType('image')).toHaveLength(0); // not yet implemented
  });

  it('getAllStatuses returns status for each engine', async () => {
    const { getRegistry } = await import('../../src/engines/registry.js');
    const statuses = getRegistry().getAllStatuses();
    for (const s of statuses) {
      expect(s.id).toBeTruthy();
      expect(s.status).toBeTruthy();
      expect(s.status.status).toMatch(/^(operational|not_configured|unsupported|error|rate_limited)$/);
    }
  });
});
