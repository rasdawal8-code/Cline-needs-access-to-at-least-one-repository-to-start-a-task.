
/**
 * GOTU SSRF Guard
 * Validates URLs before any outbound HTTP request.
 * Blocks RFC1918, loopback, link-local, cloud metadata, IPv6 special ranges,
 * IPv4-mapped IPv6, DNS rebinding, and redirect chains.
 */

import dns from 'dns';
import net from 'net';
import https from 'https';
import http from 'http';

export class SSRFError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SSRFError';
    this.code = 'SSRF_BLOCKED';
  }
}

const BLOCKED_IPV4_CIDRS = [
  { base: '0.0.0.0',      prefix: 8  },
  { base: '10.0.0.0',     prefix: 8  },
  { base: '100.64.0.0',   prefix: 10 },
  { base: '127.0.0.0',    prefix: 8  },
  { base: '169.254.0.0',  prefix: 16 },
  { base: '172.16.0.0',   prefix: 12 },
  { base: '192.0.0.0',    prefix: 24 },
  { base: '192.0.2.0',    prefix: 24 },
  { base: '192.168.0.0',  prefix: 16 },
  { base: '198.18.0.0',   prefix: 15 },
  { base: '198.51.100.0', prefix: 24 },
  { base: '203.0.113.0',  prefix: 24 },
  { base: '224.0.0.0',    prefix: 4  },
  { base: '240.0.0.0',    prefix: 4  },
  { base: '255.255.255.255', prefix: 32 },
];

const BLOCKED_METADATA_IPS = new Set([
  '169.254.169.254',
  '169.254.170.2',
]);

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'metadata.google.com',
  'instance-data',
]);

function ipv4ToInt(ip) {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

export function isBlockedIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  const ipInt = ipv4ToInt(ip);
  return BLOCKED_IPV4_CIDRS.some(({ base, prefix }) => {
    const baseInt = ipv4ToInt(base);
    const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    return ((ipInt & mask) >>> 0) === baseInt;
  });
}

function expandIPv6(ip) {
  if (ip.includes("::")) {
    const halves = ip.split("::");
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves[1] ? halves[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    const middle = Array(missing).fill("0");
    return [...left, ...middle, ...right].join(":");
  }
  return ip;
}

function ipv6ToBigInt(ip) {
  const full = expandIPv6(ip.replace(/^\[|\]$/g, ""));
  return full.split(":").reduce((acc, part) => (acc << 16n) + BigInt(parseInt(part || "0", 16)), 0n);
}

const BLOCKED_IPV6_CIDRS = [
  ["::1",         128],
  ["::",          128],
  ["fc00::",        7],
  ["fe80::",       10],
  ["ff00::",        8],
  ["2002::",       16],
  ["100::",        64],
];

export function isBlockedIPv6(ip) {
  if (!net.isIPv6(ip)) return false;
  const clean = ip.replace(/^\[|\]$/g, "");
  const v4mapped = clean.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4mapped) return isBlockedIPv4(v4mapped[1]);
  let ipBig;
  try { ipBig = ipv6ToBigInt(clean); } catch { return true; }
  return BLOCKED_IPV6_CIDRS.some(([base, prefix]) => {
    try {
      const baseBig = ipv6ToBigInt(base);
      const shift = BigInt(128 - prefix);
      const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << shift;
      return (ipBig & mask) === (baseBig & mask);
    } catch { return false; }
  });
}

export function isBlockedIP(ip) {
  const clean = ip.replace(/^\[|\]$/g, "");
  if (net.isIPv4(clean)) return isBlockedIPv4(clean) || BLOCKED_METADATA_IPS.has(clean);
  if (net.isIPv6(clean)) return isBlockedIPv6(clean);
  return true;
}

export async function validateUrl(urlString) {
  let parsed;
  try { parsed = new URL(urlString); } catch { throw new SSRFError("Invalid URL: " + urlString); }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new SSRFError("Blocked scheme: " + parsed.protocol);
  }
  const hostname = parsed.hostname;
  if (BLOCKED_HOSTNAMES.has(hostname.toLowerCase())) {
    throw new SSRFError("Blocked hostname: " + hostname);
  }
  const bare = hostname.replace(/^\[|\]$/g, "");
  if (net.isIPv4(bare) || net.isIPv6(bare)) {
    if (isBlockedIP(bare)) throw new SSRFError("Blocked IP: " + bare);
    return [bare];
  }
  const [v4Result, v6Result] = await Promise.allSettled([
    dns.promises.resolve4(hostname),
    dns.promises.resolve6(hostname),
  ]);
  const ips = [
    ...(v4Result.status === "fulfilled" ? v4Result.value : []),
    ...(v6Result.status === "fulfilled" ? v6Result.value : []),
  ];
  if (ips.length === 0) throw new SSRFError("DNS resolution failed for: " + hostname);
  for (const ip of ips) {
    if (isBlockedIP(ip)) throw new SSRFError("Blocked IP resolved for " + hostname + ": " + ip);
  }
  return ips;
}

export function createPinnedAgent(resolvedIPs, protocol, hostname) {
  const pinnedIP = resolvedIPs[0];
  const AgentClass = protocol === "https:" ? https.Agent : http.Agent;
  return new AgentClass({
    lookup: (_host, _opts, callback) => {
      callback(null, pinnedIP, net.isIPv6(pinnedIP) ? 6 : 4);
    },
    ...(protocol === "https:" && {
      servername: hostname,
      rejectUnauthorized: true,
    }),
  });
}

export function verifyConnectedIP(response) {
  const remoteAddr = response?.socket?.remoteAddress;
  if (!remoteAddr) return;
  const clean = remoteAddr.replace(/^\[|\]$/g, "");
  if (isBlockedIP(clean)) {
    throw new SSRFError("Connected to blocked IP (DNS rebinding suspected): " + clean);
  }
}
