import { SubscriptionInput, RelayConfig } from './types';
import { normalizeSubscription } from './fetcher';
import { decodeBase64Flexible } from './parser';

export interface SubscriptionUsage {
  name?: string;
  url: string;
  upload: number;
  download: number;
  used: number;
  total: number;
  remaining: number;
  upload_formatted: string;
  download_formatted: string;
  used_formatted: string;
  total_formatted: string;
  remaining_formatted: string;
  usage_percent: string;
  expire?: number;
  expire_time?: string;
  has_info: boolean;
  error?: string;
}

export interface ProfileUsageResult {
  profile?: string;
  summary: {
    total_used_formatted: string;
    total_limit_formatted: string;
    total_remaining_formatted: string;
    total_usage_percent: string;
    total_used_bytes: number;
    total_limit_bytes: number;
    total_remaining_bytes: number;
  };
  subscriptions: SubscriptionUsage[];
}

export function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const val = (bytes / Math.pow(1024, i)).toFixed(2);
  return `${val} ${units[i]}`;
}

function stringWidth(str: string): number {
  let width = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (
      (code >= 0x1100 && code <= 0x115f) ||
      (code >= 0x2e80 && code <= 0xa4cf) ||
      (code >= 0xac00 && code <= 0xd7a3) ||
      (code >= 0xf900 && code <= 0xfaff) ||
      (code >= 0xfe10 && code <= 0xfe19) ||
      (code >= 0xfe30 && code <= 0xfe6f) ||
      (code >= 0xff00 && code <= 0xff60) ||
      (code >= 0xffe0 && code <= 0xffe6)
    ) {
      width += 2;
    } else {
      width += 1;
    }
  }
  return width;
}

function padEndDisplay(str: string, targetWidth: number): string {
  const currentWidth = stringWidth(str);
  if (currentWidth >= targetWidth) return str;
  return str + ' '.repeat(targetWidth - currentWidth);
}

export function formatUsageText(result: ProfileUsageResult): string {
  const now = Math.floor(Date.now() / 1000);
  const blocks: string[] = [];

  for (const sub of result.subscriptions) {
    const name = sub.name || new URL(sub.url).hostname;
    if (!sub.has_info) {
      blocks.push(`[${name}]\n  Usage:   Unlimited\n  Expire:  no expiry`);
      continue;
    }

    let expireStr = 'no expiry';
    if (sub.expire && sub.expire > 0) {
      const days = Math.ceil((sub.expire - now) / 86400);
      const dateStr = new Date(sub.expire * 1000).toISOString().slice(0, 10);
      if (days > 0) {
        expireStr = `${days}d left (${dateStr})`;
      } else if (days === 0) {
        expireStr = `expires today (${dateStr})`;
      } else {
        expireStr = `expired ${Math.abs(days)}d ago (${dateStr})`;
      }
    }

    const usageStr = `${sub.used_formatted} / ${sub.total_formatted} (${sub.usage_percent})`;
    blocks.push(`[${name}]\n  Usage:   ${usageStr}\n  Expire:  ${expireStr}`);
  }

  if (result.subscriptions.length > 1 && result.summary.total_limit_bytes > 0) {
    const totalUsage = `${result.summary.total_used_formatted} / ${result.summary.total_limit_formatted} (${result.summary.total_usage_percent})`;
    blocks.push(`[TOTAL]\n  Usage:   ${totalUsage}\n  Remain:  ${result.summary.total_remaining_formatted}`);
  }

  return blocks.join('\n\n') + '\n';
}

function parseUserInfoHeader(header: string, url: string, name?: string): SubscriptionUsage {
  const map: Record<string, string> = {};
  header.split(';').forEach(part => {
    const [k, v] = part.trim().split('=');
    if (k && v) {
      map[k.toLowerCase()] = v;
    }
  });

  const upload = parseInt(map.upload || '0', 10) || 0;
  const download = parseInt(map.download || '0', 10) || 0;
  const total = parseInt(map.total || '0', 10) || 0;
  const used = upload + download;
  const remaining = Math.max(0, total - used);
  const expire = map.expire ? parseInt(map.expire, 10) : undefined;

  let expire_time: string | undefined;
  if (expire && expire > 0) {
    expire_time = new Date(expire * 1000).toISOString().replace('T', ' ').slice(0, 19);
  }

  return {
    name,
    url,
    upload,
    download,
    used,
    total,
    remaining,
    upload_formatted: formatBytes(upload),
    download_formatted: formatBytes(download),
    used_formatted: formatBytes(used),
    total_formatted: total > 0 ? formatBytes(total) : 'Unlimited',
    remaining_formatted: total > 0 ? formatBytes(remaining) : 'Unlimited',
    usage_percent: total > 0 ? `${((used / total) * 100).toFixed(2)}%` : '0%',
    expire,
    expire_time,
    has_info: true,
  };
}

function extractNameFromHeaders(headers: Headers): string | undefined {
  const profileTitle = headers.get('profile-title');
  if (profileTitle) {
    if (profileTitle.startsWith('base64:')) {
      const decoded = decodeBase64Flexible(profileTitle.slice(7));
      if (decoded) return decoded.trim();
    }
    return profileTitle.trim();
  }

  const disposition = headers.get('content-disposition');
  if (disposition) {
    const match = disposition.match(/filename=["']?([^"';]+)["']?/i);
    if (match && match[1]) {
      try {
        return decodeURIComponent(match[1].trim());
      } catch {
        return match[1].trim();
      }
    }
  }

  return undefined;
}

export async function fetchSingleUsage(
  sub: { name?: string; url: string; tag_prefix?: string },
  relay?: RelayConfig
): Promise<SubscriptionUsage> {
  const subUrl = sub.url;
  let res: Response | null = null;
  let directError: string | null = null;

  // 1. Direct fetch
  try {
    res = await fetch(subUrl, {
      headers: { 'User-Agent': 'sing-box' },
      cf: { cacheTtl: 300 },
    });
    if (!res.ok) {
      directError = `HTTP ${res.status}`;
      res = null;
    }
  } catch (e: any) {
    directError = e.message;
    res = null;
  }

  // 2. Relay fetch fallback
  if (!res && relay?.url) {
    try {
      const target = new URL(subUrl);
      const relayReq = new URL(relay.url);
      relayReq.pathname = target.pathname;
      relayReq.search = target.search;

      const headers: Record<string, string> = {
        'User-Agent': 'sing-box',
        'X-Target-Host': target.host,
      };
      if (relay.token) {
        headers['Authorization'] = `Bearer ${relay.token}`;
      }

      res = await fetch(relayReq.toString(), {
        headers,
        cf: { cacheTtl: 300 },
      });
    } catch (e: any) {
      return {
        name: sub.name || sub.tag_prefix?.replace(/[-_]$/, ''),
        url: subUrl,
        upload: 0,
        download: 0,
        used: 0,
        total: 0,
        remaining: 0,
        upload_formatted: '0 B',
        download_formatted: '0 B',
        used_formatted: '0 B',
        total_formatted: '0 B',
        remaining_formatted: '0 B',
        usage_percent: '0%',
        has_info: false,
        error: `Fetch failed: Direct (${directError}), Relay (${e.message})`,
      };
    }
  }

  const fallbackName = sub.name || sub.tag_prefix?.replace(/[-_]$/, '');

  if (!res || !res.ok) {
    return {
      name: fallbackName,
      url: subUrl,
      upload: 0,
      download: 0,
      used: 0,
      total: 0,
      remaining: 0,
      upload_formatted: '0 B',
      download_formatted: '0 B',
      used_formatted: '0 B',
      total_formatted: '0 B',
      remaining_formatted: '0 B',
      usage_percent: '0%',
      has_info: false,
      error: directError || `HTTP ${res?.status || 500}`,
    };
  }

  const name = sub.name || extractNameFromHeaders(res.headers) || fallbackName;
  const userInfoHeader = res.headers.get('subscription-userinfo');

  if (userInfoHeader) {
    return parseUserInfoHeader(userInfoHeader, subUrl, name);
  }

  return {
    name,
    url: subUrl,
    upload: 0,
    download: 0,
    used: 0,
    total: 0,
    remaining: 0,
    upload_formatted: '0 B',
    download_formatted: '0 B',
    used_formatted: '0 B',
    total_formatted: 'Unlimited',
    remaining_formatted: 'Unlimited',
    usage_percent: '0%',
    has_info: false,
  };
}

export async function fetchProfileUsage(
  profileName: string | undefined,
  subscriptions: SubscriptionInput[],
  relay?: RelayConfig
): Promise<ProfileUsageResult> {
  const normalized = subscriptions.map(normalizeSubscription);
  const results = await Promise.all(normalized.map(s => fetchSingleUsage(s, relay)));

  let totalUsed = 0;
  let totalLimit = 0;
  let totalRemaining = 0;

  for (const item of results) {
    if (item.has_info && item.total > 0) {
      totalUsed += item.used;
      totalLimit += item.total;
      totalRemaining += item.remaining;
    }
  }

  return {
    profile: profileName,
    summary: {
      total_used_formatted: formatBytes(totalUsed),
      total_limit_formatted: totalLimit > 0 ? formatBytes(totalLimit) : 'Unlimited',
      total_remaining_formatted: totalLimit > 0 ? formatBytes(totalRemaining) : 'Unlimited',
      total_usage_percent: totalLimit > 0 ? `${((totalUsed / totalLimit) * 100).toFixed(2)}%` : '0%',
      total_used_bytes: totalUsed,
      total_limit_bytes: totalLimit,
      total_remaining_bytes: totalRemaining,
    },
    subscriptions: results,
  };
}
