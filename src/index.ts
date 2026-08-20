import rawConfig from '../config.json';
import { Env, Profile } from './types';
import { fetchSubscriptions } from './fetcher';
import { assemble } from './assemble';

export function timingSafeEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const enc = new TextEncoder();
  const bufA = enc.encode(a);
  const bufB = enc.encode(b);
  if (bufA.byteLength !== bufB.byteLength) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < bufA.byteLength; i++) {
    diff |= bufA[i] ^ bufB[i];
  }
  return diff === 0;
}

function normalizeConfig(raw: any): { profiles: Profile[]; template?: Record<string, any> } {
  let rawProfiles: Profile[] = [];

  if (Array.isArray(raw)) {
    rawProfiles = raw;
  } else if (raw && typeof raw === 'object') {
    if (Array.isArray(raw.profiles)) {
      rawProfiles = raw.profiles;
    } else if (raw.profiles && typeof raw.profiles === 'object') {
      rawProfiles = Object.entries(raw.profiles).map(([name, p]: [string, any]) => ({
        name: p?.name || name,
        ...p,
      }));
    } else if (raw.secret_key || raw.token) {
      rawProfiles = [raw as Profile];
    }
  }

  const profiles: Profile[] = rawProfiles.map(p => ({
    ...p,
    secret_key: p.token || p.secret_key || '',
    custom_nodes: p.custom_nodes || p.nodes || [],
  }));

  return {
    profiles,
    template: raw?.template,
  };
}

const appConfig = normalizeConfig(rawConfig);

export default {
  async fetch(request: Request, _env: Env, _ctx: ExecutionContext): Promise<Response> {
    if (request.method !== 'GET') {
      return new Response('Method Not Allowed\n', { status: 405 });
    }

    const url = new URL(request.url);
    const parts = url.pathname.split('/').filter(Boolean);

    // 1. Health check
    if (parts[0] === 'health' || parts[0] === 'healthz') {
      return new Response('OK\n', {
        status: 200,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }

    // 2. Extract mode and secret key from path or query
    let mode = url.searchParams.get('mode') || 'tun';
    let key = url.searchParams.get('key') || '';

    if (parts.length === 1) {
      key = parts[0];
    } else if (parts.length === 2) {
      if (parts[0] === 'tun' || parts[0] === 'tproxy') {
        mode = parts[0];
        key = parts[1];
      } else if (parts[1] === 'tun' || parts[1] === 'tproxy') {
        key = parts[0];
        mode = parts[1];
      } else {
        return new Response('Not Found\n', { status: 404 });
      }
    } else if (!key) {
      return new Response('Not Found\n', { status: 404 });
    }

    // 3. Find matching profile
    const profile = appConfig.profiles.find(p => timingSafeEqual(p.secret_key || '', key));

    if (!profile) {
      return new Response('Not Found\n', { status: 404 });
    }

    const targetMode = mode || profile.inbound_mode || 'tun';

    // 4. Fetch subscriptions & assemble sing-box configuration
    try {
      const subNodes = await fetchSubscriptions(profile.subscriptions || []);
      const output = assemble({
        template: profile.template || appConfig.template,
        mode: targetMode,
        customNodes: profile.custom_nodes || [],
        subNodes,
      });

      return new Response(JSON.stringify(output, null, 2), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-cache',
        },
      });
    } catch (err: any) {
      console.error('[aptor] assembly error:', err);
      return new Response(err?.message || 'Internal Server Error', {
        status: 502,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }
  },
};
