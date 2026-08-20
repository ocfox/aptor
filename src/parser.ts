export function decodeBase64Flexible(str: string): string {
  let s = str.trim().replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4;
  if (pad) {
    s += '='.repeat(4 - pad);
  }
  try {
    const binary = atob(s);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
}

export function parseSubscriptionContent(content: string): Record<string, any>[] {
  const trimmed = content.trim();

  // 1. Direct JSON (Sing-Box config format with outbounds, or node array)
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed?.outbounds)) {
        return parsed.outbounds.filter((item: any) => item && typeof item === 'object');
      }
      if (Array.isArray(parsed)) {
        return parsed.filter((item: any) => item && typeof item === 'object');
      }
    } catch {
      // Not valid JSON, continue to next parsers
    }
  }

  // 2. Base64 Encoded URI links
  const decoded = decodeBase64Flexible(trimmed);
  if (decoded) {
    const nodes = parseURIs(decoded);
    if (nodes.length > 0) return nodes;
  }

  // 3. Plain text URI links line-by-line
  const nodes = parseURIs(trimmed);
  if (nodes.length > 0) return nodes;

  return [];
}

export function parseURIs(content: string): Record<string, any>[] {
  const lines = content.replace(/\r\n/g, '\n').split('\n');
  const nodes: Record<string, any>[] = [];

  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    const node = parseURI(line);
    if (node) nodes.push(node);
  }

  return nodes;
}

export function parseURI(rawURI: string): Record<string, any> | null {
  try {
    if (rawURI.startsWith('vless://')) return parseVlessURI(rawURI);
    if (rawURI.startsWith('vmess://')) return parseVmessURI(rawURI);
    if (rawURI.startsWith('trojan://')) return parseTrojanURI(rawURI);
    if (rawURI.startsWith('ss://')) return parseShadowsocksURI(rawURI);
    if (rawURI.startsWith('hysteria2://') || rawURI.startsWith('hy2://')) {
      return parseHysteria2URI(rawURI);
    }
  } catch {
    return null;
  }
  return null;
}

function parseVlessURI(rawURI: string): Record<string, any> | null {
  const u = new URL(rawURI);
  const q = u.searchParams;
  const security = q.get('security');
  const isReality = security === 'reality';
  const isTls = isReality || security === 'tls';

  const node: Record<string, any> = {
    type: 'vless',
    tag: decodeURIComponent(u.hash.replace(/^#/, '')) || u.hostname,
    server: u.hostname,
    server_port: Number(u.port) || 443,
    uuid: decodeURIComponent(u.username),
    packet_encoding: 'xudp',
  };

  const flow = q.get('flow');
  if (flow) node.flow = flow;

  if (isTls) {
    const tls: Record<string, any> = { enabled: true };
    const sni = q.get('sni');
    if (sni) tls.server_name = sni;

    const fp = q.get('fp');
    if (fp) tls.utls = { enabled: true, fingerprint: fp };

    if (isReality) {
      tls.reality = {
        enabled: true,
        ...(q.get('pbk') && { public_key: q.get('pbk') }),
        ...(q.get('sid') && { short_id: q.get('sid') }),
      };
    }
    node.tls = tls;
  }

  const netType = q.get('type');
  if (netType === 'ws') {
    node.transport = {
      type: 'ws',
      path: q.get('path') || '/',
      ...(q.get('host') && { headers: { Host: q.get('host') } }),
    };
  } else if (netType === 'grpc') {
    node.transport = {
      type: 'grpc',
      service_name: q.get('serviceName') || '',
    };
  } else if (netType === 'http' || netType === 'h2') {
    node.transport = {
      type: 'http',
      path: q.get('path') || '/',
      ...(q.get('host') && { host: q.get('host')!.split(',') }),
    };
  }

  return node;
}

function parseVmessURI(rawURI: string): Record<string, any> | null {
  const b64 = rawURI.replace(/^vmess:\/\//, '');
  const decoded = decodeBase64Flexible(b64);
  if (!decoded) return null;

  const data = JSON.parse(decoded);
  const node: Record<string, any> = {
    type: 'vmess',
    tag: data.ps || data.add,
    server: data.add,
    server_port: Number(data.port) || 443,
    uuid: data.id,
    security: data.scy || 'auto',
    alter_id: Number(data.aid) || 0,
    packet_encoding: 'xudp',
  };

  if (data.tls === 'tls') {
    node.tls = {
      enabled: true,
      server_name: data.sni || data.host || data.add,
      ...(data.fp && { utls: { enabled: true, fingerprint: data.fp } }),
    };
  }

  if (data.net === 'ws') {
    node.transport = {
      type: 'ws',
      path: data.path || '/',
      ...(data.host && { headers: { Host: data.host } }),
    };
  } else if (data.net === 'grpc') {
    node.transport = {
      type: 'grpc',
      service_name: data.path || '',
    };
  } else if (data.net === 'h2' || data.net === 'http') {
    node.transport = {
      type: 'http',
      path: data.path || '/',
      ...(data.host && { host: data.host.split(',') }),
    };
  }

  return node;
}

function parseTrojanURI(rawURI: string): Record<string, any> | null {
  const u = new URL(rawURI);
  const q = u.searchParams;

  const node: Record<string, any> = {
    type: 'trojan',
    tag: decodeURIComponent(u.hash.replace(/^#/, '')) || u.hostname,
    server: u.hostname,
    server_port: Number(u.port) || 443,
    password: decodeURIComponent(u.username),
    tls: {
      enabled: true,
      ...(q.get('sni') && { server_name: q.get('sni') }),
      ...(q.get('fp') && { utls: { enabled: true, fingerprint: q.get('fp') } }),
    },
  };

  if (q.get('type') === 'ws') {
    node.transport = {
      type: 'ws',
      path: q.get('path') || '/',
      ...(q.get('host') && { headers: { Host: q.get('host') } }),
    };
  }

  return node;
}

function parseHysteria2URI(rawURI: string): Record<string, any> | null {
  const u = new URL(rawURI);
  const q = u.searchParams;

  const node: Record<string, any> = {
    type: 'hysteria2',
    tag: decodeURIComponent(u.hash.replace(/^#/, '')) || u.hostname,
    server: u.hostname,
    server_port: Number(u.port) || 443,
    password: decodeURIComponent(u.username),
    tls: {
      enabled: true,
      ...(q.get('sni') && { server_name: q.get('sni') }),
      ...((q.get('insecure') === '1' || q.get('insecure') === 'true') && { insecure: true }),
    },
  };

  const mport = q.get('mport');
  if (mport) {
    node.server_ports = mport.split(',');
  }

  return node;
}

function parseShadowsocksURI(rawURI: string): Record<string, any> | null {
  let uri = rawURI;
  const hashIdx = uri.indexOf('#');
  const hash = hashIdx !== -1 ? uri.slice(hashIdx) : '';
  const body = hashIdx !== -1 ? uri.slice(0, hashIdx) : uri;

  // Handle legacy ss://base64(method:password@server:port)
  const ssBody = body.replace(/^ss:\/\//i, '');
  if (!ssBody.includes('@')) {
    const decoded = decodeBase64Flexible(ssBody);
    if (decoded && decoded.includes('@')) {
      uri = `ss://${decoded}${hash}`;
    }
  }

  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }

  let method = '';
  let password = '';

  if (u.username) {
    const userStr = decodeURIComponent(u.username);
    const passStr = u.password ? decodeURIComponent(u.password) : '';
    const rawUserInfo = userStr + (passStr ? `:${passStr}` : '');
    const decodedUserInfo = decodeBase64Flexible(rawUserInfo);

    if (decodedUserInfo && decodedUserInfo.includes(':')) {
      const idx = decodedUserInfo.indexOf(':');
      method = decodedUserInfo.slice(0, idx);
      password = decodedUserInfo.slice(idx + 1);
    } else {
      method = userStr;
      password = passStr;
    }
  }

  return {
    type: 'shadowsocks',
    tag: decodeURIComponent(u.hash.replace(/^#/, '')) || u.hostname,
    server: u.hostname,
    server_port: Number(u.port) || 8388,
    method,
    password,
  };
}
