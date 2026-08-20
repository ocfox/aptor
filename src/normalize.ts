const EXCLUDE_KEYWORDS = [
  '剩余流量',
  '下次重置',
  '到期',
  '套餐',
  '官网',
  '更新',
  '通知',
  '群组',
  '流量',
];

const REGION_PATTERNS: [RegExp, string][] = [
  [/香港|hk|hongkong/i, 'hk'],
  [/日本|jp|tokyo/i, 'jp'],
  [/新加坡|sg|狮城/i, 'sg'],
  [/美国|us/i, 'us'],
  [/韩国|kr/i, 'kr'],
  [/台湾|tw/i, 'tw'],
  [/英国|gb|uk/i, 'gb'],
  [/德国|de/i, 'de'],
  [/法国|fr/i, 'fr'],
  [/加拿大|ca/i, 'ca'],
];

const PROXY_PROTOCOLS = new Set([
  'vless',
  'vmess',
  'hysteria2',
  'shadowsocks',
  'trojan',
  'tuic',
  'wireguard',
  'shadowtls',
]);

export function normalizeNodes(nodes: Record<string, any>[]): Record<string, any>[] {
  const counters = new Map<string, number>();
  const clean: Record<string, any>[] = [];

  for (const node of nodes) {
    const proto = node.type;
    const tag = node.tag;

    if (!tag || typeof tag !== 'string' || !PROXY_PROTOCOLS.has(proto)) {
      continue;
    }

    const lowerTag = tag.toLowerCase();
    if (EXCLUDE_KEYWORDS.some(kw => lowerTag.includes(kw.toLowerCase()))) {
      continue;
    }

    const protoCode = proto === 'hysteria2' ? 'hy2' : proto === 'shadowsocks' ? 'ss' : proto;

    let reg = 'node';
    for (const [pattern, code] of REGION_PATTERNS) {
      if (pattern.test(lowerTag)) {
        reg = code;
        break;
      }
    }

    const key = `${reg}-${protoCode}`;
    const count = (counters.get(key) ?? 0) + 1;
    counters.set(key, count);

    clean.push({
      ...node,
      tag: `${key}-${String(count).padStart(2, '0')}`,
    });
  }

  return clean;
}
