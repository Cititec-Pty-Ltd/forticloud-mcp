import { vi } from 'vitest';
import type { CallToolResult } from '../tools/types.js';

/** Extracts the text of the first content block, failing loudly if it isn't text. */
export function textOf(result: CallToolResult): string {
  const block = result.content?.[0];
  if (!block || block.type !== 'text') {
    throw new Error(`Expected a text content block, got: ${JSON.stringify(block)}`);
  }
  return block.text;
}

/** The JSON inside a <forticloud-data> block (or the whole text when unwrapped). */
export function dataOf(result: CallToolResult): any {
  const text = textOf(result);
  const m = /^<forticloud-data>\n([\s\S]*)\n<\/forticloud-data>\n/.exec(text);
  return JSON.parse(m ? m[1] : text);
}

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

export interface Call {
  url: URL;
  method: string;
  body: any;
  auth?: string;
}

export type Route = (call: Call) => Response | Promise<Response> | undefined;

/** A token answer for a client_id. */
export const tokenFor = (clientId: string, expiresIn = 3600) =>
  json({ access_token: `tok-${clientId}`, expires_in: expiresIn, refresh_token: 'r', token_type: 'Bearer', status: 'success' });

/**
 * A fake fetch routed by "<METHOD> <host><path>", or by "token" for the IAM
 * endpoint (answered with a token for the requested client_id unless routed).
 * Unrouted requests fail the test.
 */
export function fakeForticloud(routes: Record<string, Route | Response>) {
  const calls: Call[] = [];
  const fn = vi.fn(async (u: string, init: RequestInit) => {
    const url = new URL(u);
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
    const headers = (init.headers ?? {}) as Record<string, string>;
    const call: Call = { url, method: init.method ?? 'GET', body, auth: headers.Authorization };
    calls.push(call);
    const isToken = url.host === 'customerapiauth.fortinet.com';
    const key = isToken ? 'token' : `${call.method} ${url.host}${url.pathname}`;
    const route = routes[key];
    if (route === undefined) {
      if (isToken) return tokenFor(body.client_id);
      throw new Error(`Unrouted request: ${key}`);
    }
    if (route instanceof Response) return route.clone();
    const r = await route(call);
    if (!r) throw new Error(`Route returned nothing: ${key}`);
    return r;
  });
  return { fn, calls };
}

export const FGT = 'GET api.fortigate.forticloud.com/forticloudapi/v1';
export const ASSET = 'POST support.fortinet.com/ES/api/registration/v3';
