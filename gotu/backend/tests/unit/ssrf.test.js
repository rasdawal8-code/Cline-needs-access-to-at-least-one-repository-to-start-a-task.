/**
 * Phase 4A Tests: SSRF Guard
 */

import { describe, it, expect } from 'vitest';
import { isBlockedIP, isBlockedIPv4, isBlockedIPv6 } from '../../src/middleware/ssrf.js';

describe('SSRF Guard — IPv4 blocking', () => {
  const blocked = [
    '127.0.0.1',          // loopback
    '127.0.0.254',        // loopback range
    '10.0.0.1',           // RFC1918
    '10.255.255.255',     // RFC1918
    '172.16.0.1',         // RFC1918
    '172.31.255.255',     // RFC1918
    '192.168.0.1',        // RFC1918
    '192.168.255.255',    // RFC1918
    '169.254.0.1',        // link-local
    '169.254.169.254',    // AWS/GCP/Azure metadata
    '169.254.170.2',      // AWS ECS metadata
    '100.64.0.1',         // CGNAT/shared
    '0.0.0.1',            // Current network
    '224.0.0.1',          // Multicast
    '240.0.0.1',          // Reserved
    '255.255.255.255',    // Broadcast
    '192.0.2.1',          // TEST-NET-1
    '198.51.100.1',       // TEST-NET-2
    '203.0.113.1',        // TEST-NET-3
  ];

  for (const ip of blocked) {
    it(`blocks ${ip}`, () => {
      expect(isBlockedIP(ip)).toBe(true);
    });
  }

  const allowed = [
    '1.1.1.1',            // Cloudflare DNS
    '8.8.8.8',            // Google DNS
    '104.21.0.0',         // Public Cloudflare
    '151.101.1.1',        // Fastly CDN
    '93.184.216.34',      // example.com
  ];

  for (const ip of allowed) {
    it(`allows ${ip}`, () => {
      expect(isBlockedIP(ip)).toBe(false);
    });
  }
});

describe('SSRF Guard — IPv6 blocking', () => {
  const blocked = [
    '::1',                // loopback
    'fc00::1',            // unique local
    'fd00::1',            // unique local (fd prefix)
    'fe80::1',            // link-local
    'fe80::dead:beef',    // link-local
    'ff00::1',            // multicast
    '2002::1',            // 6to4
    '::ffff:192.168.1.1', // IPv4-mapped private
    '::ffff:10.0.0.1',    // IPv4-mapped private
    '::ffff:127.0.0.1',   // IPv4-mapped loopback
    '::ffff:169.254.169.254', // IPv4-mapped metadata
  ];

  for (const ip of blocked) {
    it(`blocks ${ip}`, () => {
      expect(isBlockedIP(ip)).toBe(true);
    });
  }

  const allowed = [
    '2001:4860:4860::8888', // Google DNS IPv6
    '2606:4700:4700::1111', // Cloudflare DNS IPv6
  ];

  for (const ip of allowed) {
    it(`allows ${ip}`, () => {
      expect(isBlockedIP(ip)).toBe(false);
    });
  }
});

describe('SSRF Guard — validateUrl', () => {
  it('is importable and returns a function', async () => {
    const { validateUrl } = await import('../../src/middleware/ssrf.js');
    expect(typeof validateUrl).toBe('function');
  });

  it('rejects non-http schemes', async () => {
    const { validateUrl, SSRFError } = await import('../../src/middleware/ssrf.js');
    await expect(validateUrl('file:///etc/passwd')).rejects.toThrow(SSRFError);
    await expect(validateUrl('ftp://example.com')).rejects.toThrow(SSRFError);
    await expect(validateUrl('gopher://evil.com')).rejects.toThrow(SSRFError);
  });

  it('rejects blocked hostname: localhost', async () => {
    const { validateUrl, SSRFError } = await import('../../src/middleware/ssrf.js');
    await expect(validateUrl('http://localhost/admin')).rejects.toThrow(SSRFError);
  });

  it('rejects blocked hostname: metadata.google.internal', async () => {
    const { validateUrl, SSRFError } = await import('../../src/middleware/ssrf.js');
    await expect(validateUrl('http://metadata.google.internal/')).rejects.toThrow(SSRFError);
  });

  it('rejects direct IPv4 loopback URL', async () => {
    const { validateUrl, SSRFError } = await import('../../src/middleware/ssrf.js');
    await expect(validateUrl('http://127.0.0.1/')).rejects.toThrow(SSRFError);
  });

  it('rejects direct metadata IP URL', async () => {
    const { validateUrl, SSRFError } = await import('../../src/middleware/ssrf.js');
    await expect(validateUrl('http://169.254.169.254/latest/meta-data/')).rejects.toThrow(SSRFError);
  });

  it('rejects direct RFC1918 IPv4 URL', async () => {
    const { validateUrl, SSRFError } = await import('../../src/middleware/ssrf.js');
    await expect(validateUrl('http://192.168.1.1/')).rejects.toThrow(SSRFError);
    await expect(validateUrl('http://10.0.0.1/')).rejects.toThrow(SSRFError);
  });

  it('rejects IPv6 loopback URL', async () => {
    const { validateUrl, SSRFError } = await import('../../src/middleware/ssrf.js');
    await expect(validateUrl('http://[::1]/')).rejects.toThrow(SSRFError);
  });
});
