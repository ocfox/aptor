import rawConfig from '../config.json';
import configSchema from './schema.json';
import { Env, Profile, RelayConfig } from './types';
import { fetchSubscriptions } from './fetcher';
import { assemble } from './assemble';
import { fetchProfileUsage, formatUsageText } from './usage';

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

interface NormalizedAppConfig {
  relay?: RelayConfig;
  profiles: Profile[];
  template?: Record<string, any>;
}

function normalizeConfig(raw: any): NormalizedAppConfig {
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
    relay: raw?.relay,
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

    // 1. Health check & Schema endpoints
    if (parts[0] === 'health' || parts[0] === 'healthz') {
      return new Response('OK\n', {
        status: 200,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }

    if (parts[0] === 'schema' || parts[0] === 'schema.json') {
      return new Response(JSON.stringify(configSchema, null, 2), {
        status: 200,
        headers: {
          'Content-Type': 'application/schema+json; charset=utf-8',
          'Cache-Control': 'public, max-age=86400',
        },
      });
    }

    // 2. Extract action/mode and secret key from path or query
    let isUsage = false;
    let mode = url.searchParams.get('mode') || 'tun';
    let key = url.searchParams.get('key') || '';

    if (parts.length === 1) {
      key = parts[0];
    } else if (parts.length === 2) {
      if (parts[0] === 'usage') {
        isUsage = true;
        key = parts[1];
      } else if (parts[1] === 'usage') {
        isUsage = true;
        key = parts[0];
      } else if (parts[0] === 'tun' || parts[0] === 'tproxy') {
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

    const relay = profile.relay || appConfig.relay;

    // 4. Handle /usage query (Plaintext by default, JSON on ?json / ?format=json)
    if (isUsage) {
      try {
        const wantsJson =
          url.searchParams.get('format') === 'json' ||
          url.searchParams.has('json') ||
          (request.headers.get('accept')?.includes('application/json') &&
            !request.headers.get('accept')?.includes('text/html') &&
            !request.headers.get('user-agent')?.includes('curl'));

        const usageData = await fetchProfileUsage(profile.name, profile.subscriptions || [], relay);

        if (wantsJson) {
          return new Response(JSON.stringify(usageData, null, 2), {
            status: 200,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Cache-Control': 'no-cache',
            },
          });
        }

        const textOutput = formatUsageText(usageData);
        return new Response(textOutput, {
          status: 200,
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-cache',
          },
        });
      } catch (err: any) {
        console.error('[aptor] usage fetch error:', err);
        return new Response(`Error: ${err?.message || 'Usage fetch failed'}\n`, {
          status: 500,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' },
        });
      }
    }

    const targetMode = mode || profile.inbound_mode || 'tun';

    // 5. Fetch subscriptions & assemble sing-box configuration
    try {
      const subNodes = await fetchSubscriptions(profile.subscriptions || [], relay);
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
