import defaultTemplate from './template.json';
import { normalizeNodes } from './normalize';
import { parseURI } from './parser';
import { CustomNodeInput } from './types';

export interface AssembleOptions {
  template?: Record<string, any>;
  mode?: string;
  customNodes?: CustomNodeInput[];
  subNodes?: Record<string, any>[];
}

export function normalizeCustomNodes(customNodes: CustomNodeInput[]): Record<string, any>[] {
  const result: Record<string, any>[] = [];

  for (const item of customNodes) {
    if (typeof item === 'string') {
      const parsed = parseURI(item);
      if (parsed) {
        result.push({ ...parsed, _groups: ['Proxy'] });
      }
    } else if (item && typeof item === 'object') {
      if (typeof item.node === 'string' || typeof item.uri === 'string') {
        const rawUri = item.node || item.uri;
        const parsed = parseURI(rawUri!);
        if (parsed) {
          result.push({
            ...parsed,
            _groups: item.groups && item.groups.length > 0 ? item.groups : ['Proxy'],
          });
        }
      } else if (item.type) {
        // Direct sing-box node object
        result.push(JSON.parse(JSON.stringify(item)));
      }
    }
  }

  return result;
}

export function assemble({
  template = defaultTemplate,
  mode = 'tun',
  customNodes = [],
  subNodes = [],
}: AssembleOptions): Record<string, any> {
  const config = JSON.parse(JSON.stringify(template));
  const isTproxy = (mode || '').toLowerCase() === 'tproxy';

  // 1. Configure Inbounds
  if (isTproxy) {
    config.inbounds = [
      { type: 'mixed', tag: 'mixed-in', listen: '::', listen_port: 7890 },
      { type: 'tproxy', tag: 'tproxy-in', listen: '::', listen_port: 7895 },
    ];
  } else {
    config.inbounds = [
      { type: 'mixed', tag: 'mixed-in', listen: '::', listen_port: 7890 },
      {
        type: 'tun',
        tag: 'tun-in',
        address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
        mtu: 1500,
        auto_route: true,
        auto_redirect: true,
        strict_route: true,
        stack: 'mixed',
      },
    ];
  }

  // 2. Prepare Nodes & Tags
  const resolvedCustom = normalizeCustomNodes(customNodes);
  const normalizedSub = normalizeNodes(subNodes);
  const allNodes = [...resolvedCustom, ...normalizedSub];

  const allTags: string[] = [];
  const groupTags: Record<string, string[]> = {};
  const tagCounts: Record<string, number> = {};

  for (const node of allNodes) {
    if (isTproxy) {
      node.routing_mark = 255;
    } else {
      delete node.routing_mark;
    }

    // Extract groups
    let groups: string[] = [];
    if (Array.isArray(node._groups) && node._groups.length > 0) {
      groups = node._groups.filter(Boolean);
    } else if (Array.isArray(node.groups) && node.groups.length > 0) {
      groups = node.groups.filter(Boolean);
    }
    if (groups.length === 0) {
      groups = ['Proxy'];
    }

    delete node._groups;
    delete node.groups;

    let tag = node.tag;
    if (!tag || typeof tag !== 'string') continue;

    // Deduplicate tag names
    if (tagCounts[tag]) {
      tagCounts[tag]++;
      tag = `${tag}-${tagCounts[tag]}`;
      node.tag = tag;
    } else {
      tagCounts[tag] = 1;
    }

    allTags.push(tag);

    for (const g of groups) {
      if (!groupTags[g]) groupTags[g] = [];
      groupTags[g].push(tag);
    }
  }

  // 3. Resolve Outbound Selectors
  const proxyTags = groupTags['Proxy']?.length ? groupTags['Proxy'] : allTags;

  let defNode = 'direct';
  if (proxyTags.includes('light')) {
    defNode = 'light';
  } else if (proxyTags.length > 0) {
    defNode = proxyTags[0];
  }

  let aiOutbounds: string[];
  let aiDef: string;
  const aiTags = groupTags['AI'];
  if (aiTags && aiTags.length > 0) {
    aiOutbounds = [...aiTags, 'Proxy', 'direct'];
    aiDef = aiTags[0];
  } else {
    aiOutbounds = [defNode, 'Proxy'];
    aiDef = defNode;
  }

  const directOut: Record<string, any> = { type: 'direct', tag: 'direct' };
  if (isTproxy) {
    directOut.routing_mark = 255;
  }

  config.outbounds = [
    {
      type: 'selector',
      tag: 'Proxy',
      outbounds: [...proxyTags, 'direct'],
      default: defNode,
    },
    {
      type: 'selector',
      tag: 'AI',
      outbounds: aiOutbounds,
      default: aiDef,
    },
    {
      type: 'selector',
      tag: 'Others',
      outbounds: ['Proxy', 'direct'],
    },
    {
      type: 'selector',
      tag: 'CN',
      outbounds: ['direct', 'Proxy'],
    },
    directOut,
    {
      type: 'block',
      tag: 'block',
    },
    ...allNodes,
  ];

  return config;
}
