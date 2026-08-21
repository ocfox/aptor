import { SubscriptionInput, NormalizedSubscription, RelayConfig } from './types';
import { parseSubscriptionContent } from './parser';

export function normalizeSubscription(sub: SubscriptionInput): NormalizedSubscription {
  if (typeof sub === 'string') {
    return { url: sub, groups: ['Proxy'] };
  }
  const toArray = (v?: string | string[]) => {
    if (!v) return undefined;
    return Array.isArray(v) ? v.filter(Boolean) : [v];
  };

  return {
    url: sub.url,
    tag_prefix: sub.tag_prefix,
    groups: sub.groups && sub.groups.length > 0 ? sub.groups : ['Proxy'],
    exclude: toArray(sub.exclude),
    include: toArray(sub.include),
  };
}

async function doFetch(url: string, headers: Record<string, string>): Promise<string> {
  const res = await fetch(url, {
    headers,
    cf: {
      cacheTtl: 600,
      cacheEverything: true,
    },
  });

  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }

  return res.text();
}

export async function fetchSubscription(
  sub: NormalizedSubscription,
  relay?: RelayConfig
): Promise<Record<string, any>[]> {
  let text = '';
  let directError: Error | null = null;

  // 1. Attempt direct fetch first from Cloudflare edge
  try {
    text = await doFetch(sub.url, { 'User-Agent': 'sing-box' });
  } catch (err: any) {
    directError = err;
  }

  // 2. If direct fetch fails and relay is configured, fallback to relay
  if (!text && relay?.url) {
    try {
      const target = new URL(sub.url);
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

      text = await doFetch(relayReq.toString(), headers);
    } catch (relayErr: any) {
      throw new Error(`Failed to fetch ${sub.url} (Direct: ${directError?.message}, Relay: ${relayErr.message})`);
    }
  } else if (!text && directError) {
    throw directError;
  }

  let rawNodes = parseSubscriptionContent(text);

  // Apply subscription-level exclude / include filters
  if (sub.exclude && sub.exclude.length > 0) {
    rawNodes = rawNodes.filter(node => {
      const tag = String(node.tag || '');
      const server = String(node.server || '');
      const text = `${tag} ${server}`.toLowerCase();
      return !sub.exclude!.some(kw => text.includes(kw.toLowerCase()));
    });
  }

  if (sub.include && sub.include.length > 0) {
    rawNodes = rawNodes.filter(node => {
      const tag = String(node.tag || '');
      const server = String(node.server || '');
      const text = `${tag} ${server}`.toLowerCase();
      return sub.include!.some(kw => text.includes(kw.toLowerCase()));
    });
  }

  return rawNodes.map(node => {
    return {
      ...node,
      ...(sub.tag_prefix && { _tag_prefix: sub.tag_prefix }),
      _groups: sub.groups,
    };
  });
}

export async function fetchSubscriptions(
  subscriptions: SubscriptionInput[],
  relay?: RelayConfig
): Promise<Record<string, any>[]> {
  const normalized = subscriptions.map(normalizeSubscription);
  const results = await Promise.allSettled(
    normalized.map(sub => fetchSubscription(sub, relay))
  );

  const allNodes: Record<string, any>[] = [];
  let lastError: Error | null = null;

  for (const result of results) {
    if (result.status === 'fulfilled') {
      allNodes.push(...result.value);
    } else {
      lastError = result.reason instanceof Error ? result.reason : new Error(String(result.reason));
    }
  }

  if (allNodes.length === 0 && lastError) {
    throw lastError;
  }

  return allNodes;
}
