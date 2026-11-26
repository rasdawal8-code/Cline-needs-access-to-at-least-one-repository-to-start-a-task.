/**
 * GOTU Username Intelligence Engine
 * Platform-specific adapters with verified detection methods.
 * No result is fabricated. Unsupported platforms report UNSUPPORTED.
 */

import { IntelligenceEngine, EngineStatus, Confidence } from '../base/engine.js';
import https from 'https';
import http from 'http';

// Safe HTTP fetch with timeout (no SSRF needed here - targets are public platforms)
async function safeFetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout ?? 10000;
    const parsed = new URL(url);
    const transport = parsed.protocol === 'https:' ? https : http;
    const req = transport.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; GOTU-OSINT/1.0; +https://gotu.local)',
        'Accept': 'application/json, text/html',
        ...options.headers,
      },
      timeout,
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    setTimeout(() => { req.destroy(); reject(new Error('Request timeout')); }, timeout);
  });
}

// ─── Platform adapter interface ───────────────────────────────────────────────

class GitHubAdapter {
  get id() { return 'github'; }
  get name() { return 'GitHub'; }
  get method() { return 'api'; }
  get notes() { return 'GitHub REST API. No key: 60/hr. With token: 5000/hr.'; }
  get requiresKey() { return false; }

  async check(username) {
    try {
      const headers = {};
      const token = process.env.GITHUB_TOKEN;
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const res = await safeFetch(`https://api.github.com/users/${encodeURIComponent(username)}`, { headers });
      if (res.status === 404) return { found: false, platform: this.id };
      if (res.status !== 200) return { found: false, platform: this.id, error: `HTTP ${res.status}` };
      const data = JSON.parse(res.body);
      if (!data.login || data.login.toLowerCase() !== username.toLowerCase()) {
        return { found: false, platform: this.id };
      }
      return {
        found: true, platform: this.id, platformName: this.name,
        confidence: Confidence.CONFIRMED,
        profileUrl: data.html_url,
        username: data.login,
        displayName: data.name ?? null,
        bio: data.bio ?? null,
        publicRepos: data.public_repos,
        followers: data.followers,
        createdAt: data.created_at,
        avatarUrl: data.avatar_url,
        location: data.location ?? null,
        company: data.company ?? null,
        blog: data.blog ?? null,
        sourceUrl: data.html_url,
      };
    } catch (e) {
      return { found: false, platform: this.id, error: e.message };
    }
  }
}

class RedditAdapter {
  get id() { return 'reddit'; }
  get name() { return 'Reddit'; }
  get method() { return 'public_json_api'; }
  get requiresKey() { return false; }

  async check(username) {
    try {
      const res = await safeFetch(`https://www.reddit.com/user/${encodeURIComponent(username)}/about.json`, {
        headers: { 'Accept': 'application/json' }
      });
      if (res.status === 404 || res.status === 403) return { found: false, platform: this.id };
      if (res.status !== 200) return { found: false, platform: this.id, error: `HTTP ${res.status}` };
      const data = JSON.parse(res.body);
      const u = data?.data;
      if (!u?.name || u.name.toLowerCase() !== username.toLowerCase()) {
        return { found: false, platform: this.id };
      }
      return {
        found: true, platform: this.id, platformName: this.name,
        confidence: Confidence.CONFIRMED,
        profileUrl: `https://www.reddit.com/user/${u.name}`,
        username: u.name,
        commentKarma: u.comment_karma,
        linkKarma: u.link_karma,
        createdAt: new Date(u.created_utc * 1000).toISOString(),
        isSuspended: u.is_suspended ?? false,
        sourceUrl: `https://www.reddit.com/user/${u.name}`,
      };
    } catch (e) {
      return { found: false, platform: this.id, error: e.message };
    }
  }
}

class HackerNewsAdapter {
  get id() { return 'hackernews'; }
  get name() { return 'Hacker News'; }
  get method() { return 'algolia_api'; }
  get requiresKey() { return false; }

  async check(username) {
    try {
      const res = await safeFetch(`https://hn.algolia.com/api/v1/users/${encodeURIComponent(username)}`);
      if (res.status === 404) return { found: false, platform: this.id };
      if (res.status !== 200) return { found: false, platform: this.id, error: `HTTP ${res.status}` };
      const data = JSON.parse(res.body);
      if (!data.username || data.username.toLowerCase() !== username.toLowerCase()) {
        return { found: false, platform: this.id };
      }
      return {
        found: true, platform: this.id, platformName: this.name,
        confidence: Confidence.CONFIRMED,
        profileUrl: `https://news.ycombinator.com/user?id=${data.username}`,
        username: data.username,
        karma: data.karma,
        about: data.about ?? null,
        createdAt: data.created_at,
        sourceUrl: `https://news.ycombinator.com/user?id=${data.username}`,
      };
    } catch (e) {
      return { found: false, platform: this.id, error: e.message };
    }
  }
}

class GitLabAdapter {
  get id() { return 'gitlab'; }
  get name() { return 'GitLab'; }
  get method() { return 'public_api'; }
  get requiresKey() { return false; }

  async check(username) {
    try {
      const res = await safeFetch(`https://gitlab.com/api/v4/users?username=${encodeURIComponent(username)}`);
      if (res.status !== 200) return { found: false, platform: this.id, error: `HTTP ${res.status}` };
      const data = JSON.parse(res.body);
      if (!Array.isArray(data) || data.length === 0) return { found: false, platform: this.id };
      const user = data.find(u => u.username.toLowerCase() === username.toLowerCase());
      if (!user) return { found: false, platform: this.id };
      return {
        found: true, platform: this.id, platformName: this.name,
        confidence: Confidence.CONFIRMED,
        profileUrl: user.web_url,
        username: user.username,
        displayName: user.name,
        avatarUrl: user.avatar_url,
        createdAt: user.created_at,
        publicRepos: user.public_repos ?? null,
        sourceUrl: user.web_url,
      };
    } catch (e) {
      return { found: false, platform: this.id, error: e.message };
    }
  }
}

class KeybaseAdapter {
  get id() { return 'keybase'; }
  get name() { return 'Keybase'; }
  get method() { return 'public_api'; }
  get requiresKey() { return false; }

  async check(username) {
    try {
      const res = await safeFetch(`https://keybase.io/_/api/1.0/user/lookup.json?username=${encodeURIComponent(username)}`);
      if (res.status !== 200) return { found: false, platform: this.id };
      const data = JSON.parse(res.body);
      if (data.status?.code !== 0 || !data.them?.length) return { found: false, platform: this.id };
      const user = data.them[0];
      return {
        found: true, platform: this.id, platformName: this.name,
        confidence: Confidence.CONFIRMED,
        profileUrl: `https://keybase.io/${user.basics?.username}`,
        username: user.basics?.username,
        displayName: user.profile?.full_name ?? null,
        bio: user.profile?.bio ?? null,
        location: user.profile?.location ?? null,
        sourceUrl: `https://keybase.io/${user.basics?.username}`,
      };
    } catch (e) {
      return { found: false, platform: this.id, error: e.message };
    }
  }
}

class NpmAdapter {
  get id() { return 'npm'; }
  get name() { return 'npm Registry'; }
  get method() { return 'public_registry_api'; }
  get requiresKey() { return false; }

  async check(username) {
    try {
      const res = await safeFetch(`https://registry.npmjs.org/-/user/org.couchdb.user:${encodeURIComponent(username)}`);
      if (res.status === 404) return { found: false, platform: this.id };
      if (res.status !== 200) return { found: false, platform: this.id, error: `HTTP ${res.status}` };
      const data = JSON.parse(res.body);
      if (!data.name) return { found: false, platform: this.id };
      return {
        found: true, platform: this.id, platformName: this.name,
        confidence: Confidence.CONFIRMED,
        profileUrl: `https://www.npmjs.com/~${data.name}`,
        username: data.name,
        email: data.email ?? null,
        sourceUrl: `https://www.npmjs.com/~${data.name}`,
      };
    } catch (e) {
      return { found: false, platform: this.id, error: e.message };
    }
  }
}

// Explicitly unsupported platforms — documented clearly, never fabricated
const UNSUPPORTED_PLATFORMS = [
  { id: 'instagram',  name: 'Instagram',  reason: 'No reliable public API available without authentication since 2019' },
  { id: 'tiktok',     name: 'TikTok',     reason: 'No official public user lookup API' },
  { id: 'facebook',   name: 'Facebook',   reason: 'No public profile API without authentication' },
  { id: 'linkedin',   name: 'LinkedIn',   reason: 'No public profile scraping API' },
];

// Platforms requiring API keys
const KEY_REQUIRED_PLATFORMS = [
  { id: 'twitter', name: 'X (Twitter)', envKey: 'TWITTER_API_KEY', tier: 'Basic ($100/mo)' },
  { id: 'youtube',  name: 'YouTube',    envKey: 'GOOGLE_API_KEY',  tier: 'Free (requires key)' },
];

// ─── Username Engine ───────────────────────────────────────────────────────────

export class UsernameEngine extends IntelligenceEngine {
  constructor() {
    super();
    this._adapters = [
      new GitHubAdapter(),
      new RedditAdapter(),
      new HackerNewsAdapter(),
      new GitLabAdapter(),
      new KeybaseAdapter(),
      new NpmAdapter(),
    ];
  }

  get id()   { return 'username'; }
  get name() { return 'Username Intelligence'; }
  get supportedInputTypes() { return ['username']; }
  get requiredApiKeys() { return []; }

  async execute(context) {
    const result = this.emptyResult();
    const { indicatorValue: username } = context;

    // Run all adapters in parallel
    const checks = await Promise.allSettled(
      this._adapters.map(adapter => adapter.check(username))
    );

    for (const outcome of checks) {
      result.apiCallsUsed++;
      if (outcome.status === 'rejected') {
        result.errors.push(outcome.reason?.message ?? 'Unknown adapter error');
        continue;
      }
      const check = outcome.value;
      if (check.error) result.errors.push(`${check.platform}: ${check.error}`);
      if (!check.found) continue;

      // Add finding
      const finding = this.makeFinding(
        'username_profile_found',
        {
          platform:     check.platform,
          platformName: check.platformName,
          profileUrl:   check.profileUrl,
          username:     check.username,
          displayName:  check.displayName ?? null,
          bio:          check.bio ?? null,
          extra:        check,
        },
        check.confidence ?? Confidence.POSSIBLE,
        check.sourceUrl,
        check.platformName,
      );
      result.findings.push(finding);

      // Extract leads from profile data
      if (check.blog && check.blog.includes('.')) {
        try {
          const blogUrl = check.blog.startsWith('http') ? check.blog : `https://${check.blog}`;
          const domain = new URL(blogUrl).hostname;
          if (domain && domain !== '') {
            result.leads.push(this.makeLead('domain', domain, Confidence.POSSIBLE));
          }
        } catch {}
      }
      if (check.company) {
        result.leads.push(this.makeLead('organization', check.company.replace(/^@/, ''), Confidence.POSSIBLE));
      }
    }

    // Record unsupported platforms as metadata findings
    for (const up of UNSUPPORTED_PLATFORMS) {
      result.findings.push(this.makeFinding(
        'platform_not_supported',
        { platform: up.id, platformName: up.name, reason: up.reason },
        Confidence.CONFIRMED,
        null,
        up.name,
      ));
    }

    // Record key-required platforms
    for (const kp of KEY_REQUIRED_PLATFORMS) {
      const configured = !!process.env[kp.envKey];
      result.findings.push(this.makeFinding(
        configured ? 'platform_check_available' : 'platform_requires_api_key',
        { platform: kp.id, platformName: kp.name, envKey: kp.envKey, tier: kp.tier, configured },
        Confidence.CONFIRMED,
        null,
        kp.name,
      ));
    }

    return result;
  }

  getPlatformStatus() {
    return {
      supported: this._adapters.map(a => ({ id: a.id, name: a.name, method: a.method, requiresKey: a.requiresKey })),
      unsupported: UNSUPPORTED_PLATFORMS,
      keyRequired: KEY_REQUIRED_PLATFORMS.map(p => ({ ...p, configured: !!process.env[p.envKey] })),
    };
  }
}
