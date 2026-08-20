import { SubscriptionInput, NormalizedSubscription } from './types';
import { parseSubscriptionContent } from './parser';

export function normalizeSubscription(sub: SubscriptionInput): NormalizedSubscription {
  if (typeof sub === 'string') {
    return { url: sub, groups: ['Proxy'] };
  }
  return {
    url: sub.url,
    tag_prefix: sub.tag_prefix,
    groups: sub.groups && sub.groups.length > 0 ? sub.groups : ['Proxy'],
  };
}

export async function fetchSubscription(sub: NormalizedSubscription): Promise<Record<string, any>[]> {
  const res = await fetch(sub.url, {
    headers: {
      'User-Agent': 'sing-box',
    },
    cf: {
      cacheTtl: 600,
      cacheEverything: true,
    },
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch ${sub.url}: ${res.status} ${res.statusText}`);
  }

  const text = await res.text();
  const rawNodes = parseSubscriptionContent(text);

  return rawNodes.map(node => {
    let tag = node.tag;
    if (sub.tag_prefix && tag && typeof tag === 'string') {
      tag = `${sub.tag_prefix}${tag}`;
    }
    return {
      ...node,
      ...(tag && { tag }),
      _groups: sub.groups,
    };
  });
}

export async function fetchSubscriptions(
  subscriptions: SubscriptionInput[]
): Promise<Record<string, any>[]> {
  const normalized = subscriptions.map(normalizeSubscription);
  const results = await Promise.allSettled(normalized.map(fetchSubscription));

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
