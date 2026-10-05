import { beforeAll, describe, expect, it, vi } from 'vitest';
import { gzipSync } from 'node:zlib';
import { generateKeyPairSync, sign, createHash, createHmac, randomUUID, randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';

process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = ':memory:';
// TEST_DB=postgres runs the same suite against Postgres (in-process PGlite).
if (process.env.TEST_DB === 'postgres' || process.env.npm_lifecycle_event === 'test:postgres') process.env.POSTGRES_URL = 'pglite://memory';
process.env.SUPABASE_URL = 'https://test-project.supabase.co';
process.env.SUPABASE_JWT_SECRET = 'test-jwt-secret-for-unit-tests-only-0123456789';
process.env.LOG_LEVEL = 'error';
process.env.FIREBASE_PROJECT_ID = 'test-firebase-project';
process.env.STORAGE_DRIVER = 'memory';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key';
process.env.ADMIN_EMAILS = 'admin@example.com';
process.env.TELEGRAM_BOT_TOKEN = 'test-bot-token';
process.env.TELEGRAM_ADMIN_CHAT_IDS = '111';
// Placeholder payment credentials; Cashfree is always mocked in tests.
process.env.CASHFREE_APP_ID = 'test-app';
process.env.CASHFREE_SECRET_KEY = 'test-secret';

let app: typeof import('../src/app.js').app;
let db: typeof import('../src/db/database.js').db;

beforeAll(async () => {
  app = (await import('../src/app.js')).app;
  db = (await import('../src/db/database.js')).db;
  // Treat every test account as created before the PC limit (the clock passes the real cutoff); the
  // plan tests move individual accounts after it.
  (await import('../src/modules/billing.js')).planPolicy.desktopLimitSince = '2100-01-01T00:00:00Z';
});

async function tokenFor(sub: string, email: string) {
  return new SignJWT({ email, role: 'authenticated', user_metadata: { full_name: email.split('@')[0] } })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(sub)
    .setIssuer('https://test-project.supabase.co/auth/v1')
    .setAudience('authenticated')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(new TextEncoder().encode(process.env.SUPABASE_JWT_SECRET));
}

function desktopKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), privateKey };
}

type Keys = ReturnType<typeof desktopKeys>;

async function call(method: string, path: string, opts: { token?: string; body?: unknown; keys?: Keys; deviceId?: string; headers?: Record<string, string> } = {}) {
  const body = opts.body === undefined ? '' : JSON.stringify(opts.body);
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...(opts.headers ?? {}) };
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  if (opts.deviceId) headers['X-BK-Device-Id'] = opts.deviceId;
  if (opts.keys) {
    const ts = String(Date.now());
    const payload = `${method}\n${path}\n${ts}\n${createHash('sha256').update(body).digest('hex')}`;
    headers['X-BK-Timestamp'] = ts;
    headers['X-BK-Signature'] = sign(null, Buffer.from(payload), opts.keys.privateKey).toString('base64');
  }
  const res = await app.request(`http://localhost${path}`, { method, headers, body: method === 'GET' ? undefined : body || undefined });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

async function setupDesktop(token: string) {
  const keys = desktopKeys();
  const res = await call('POST', '/v1/devices/register', {
    token,
    keys,
    body: { kind: 'desktop', name: 'Test PC', platform: 'windows', appVersion: '1.0.3', publicKey: keys.publicPem },
  });
  expect(res.status).toBe(201);
  return { keys, id: res.json.data.id as string };
}

async function pairPhone(userToken: string, desktop: { keys: Keys; id: string }) {
  const issued = await call('POST', '/v1/pairing/tokens', { token: userToken, keys: desktop.keys, deviceId: desktop.id, body: {} });
  expect(issued.status).toBe(201);
  const claim = await call('POST', '/v1/pairing/claim', {
    token: userToken,
    body: { token: issued.json.data.token, mobile: { installationId: randomUUID(), name: 'Test Phone', platform: 'android', appVersion: '1.0' } },
  });
  expect(claim.status).toBe(200);
  return { mobileId: claim.json.data.mobile.id as string, pairingToken: issued.json.data.token as string };
}

/**
 * Acts as the PC for live relay requests: marks it connected and answers relay.request events,
 * the same way BambooKit Desktop does over its realtime stream.
 */
async function serveDesktop(token: string, desktop: { keys: Keys; id: string }, answer: (kind: string, params: any) => unknown) {
  const bus = await import('../src/realtime/bus.js');
  const me = (await call('GET', '/v1/me', { token })).json.data;
  bus.markConnected(desktop.id);
  const off = bus.subscribe(me.id, (event) => {
    if (event.type !== 'relay.request' || event.deviceId !== desktop.id) return;
    const { id, kind, params } = event.payload as any;
    void call('POST', `/v1/relay/${id}/response`, { token, deviceId: desktop.id, keys: desktop.keys, body: { data: answer(kind, params) } });
  });
  return () => {
    off();
    bus.markDisconnected(desktop.id);
  };
}

describe('authentication', () => {
  it('rejects requests without a token', async () => {
    expect((await call('GET', '/v1/me')).status).toBe(401);
  });

  it('rejects tokens signed with the wrong secret', async () => {
    const bad = await new SignJWT({}).setProtectedHeader({ alg: 'HS256' }).setSubject('x').setIssuer('https://test-project.supabase.co/auth/v1')
      .setAudience('authenticated').setExpirationTime('1h').sign(new TextEncoder().encode('wrong-secret-wrong-secret-wrong'));
    expect((await call('GET', '/v1/me', { token: bad })).status).toBe(401);
  });

  it('rejects forged tokens that claim the Firebase issuer', async () => {
    const forged = await new SignJWT({ email: 'x@example.com', email_verified: true })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('firebase-uid')
      .setIssuer('https://securetoken.google.com/test-firebase-project')
      .setAudience('test-firebase-project')
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode(process.env.SUPABASE_JWT_SECRET));
    const res = await call('GET', '/v1/me', { token: forged });
    expect(res.status).toBe(401);
  });

  it('returns the Supabase user for a valid token', async () => {
    const token = await tokenFor('user-auth-1', 'a@example.com');
    const res = await call('GET', '/v1/me', { token });
    expect(res.status).toBe(200);
    expect(res.json.data).toMatchObject({ id: 'user-auth-1', email: 'a@example.com' });
  });
});

describe('desktop registration', () => {
  it('requires proof of key possession', async () => {
    const token = await tokenFor('user-reg-1', 'r@example.com');
    const keys = desktopKeys();
    const body = { kind: 'desktop', name: 'PC', platform: 'windows', publicKey: keys.publicPem };
    expect((await call('POST', '/v1/devices/register', { token, body })).status).toBe(401);
    const other = desktopKeys();
    expect((await call('POST', '/v1/devices/register', { token, body, keys: other })).status).toBe(401);
    expect((await call('POST', '/v1/devices/register', { token, body, keys })).status).toBe(201);
    // Re-registering the same key is idempotent.
    expect((await call('POST', '/v1/devices/register', { token, body, keys })).status).toBe(200);
  });

  it('rejects unsigned device-channel requests', async () => {
    const token = await tokenFor('user-reg-2', 'r2@example.com');
    const desktop = await setupDesktop(token);
    expect((await call('POST', '/v1/sync', { token, deviceId: desktop.id, body: {} })).status).toBe(401);
    expect((await call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: {} })).status).toBe(200);
  });
});

describe('QR pairing', () => {
  it('pairs a phone once and rejects reuse', async () => {
    const token = await tokenFor('user-pair-1', 'p@example.com');
    const desktop = await setupDesktop(token);
    const { mobileId, pairingToken } = await pairPhone(token, desktop);

    const devices = await call('GET', '/v1/devices', { token });
    const pc = devices.json.data.find((d: any) => d.id === desktop.id);
    expect(pc.linkedDevices.map((l: any) => l.id)).toContain(mobileId);

    const reuse = await call('POST', '/v1/pairing/claim', {
      token,
      body: { token: pairingToken, mobile: { installationId: randomUUID(), name: 'Other', platform: 'android' } },
    });
    expect(reuse.status).toBe(410);
    expect(reuse.json.error.code).toBe('PAIRING_TOKEN_USED');
  });

  it('rejects a token from a different account', async () => {
    const owner = await tokenFor('user-pair-2', 'owner@example.com');
    const attacker = await tokenFor('user-pair-3', 'attacker@example.com');
    const desktop = await setupDesktop(owner);
    const issued = await call('POST', '/v1/pairing/tokens', { token: owner, keys: desktop.keys, deviceId: desktop.id, body: {} });
    const res = await call('POST', '/v1/pairing/claim', {
      token: attacker,
      body: { token: issued.json.data.token, mobile: { installationId: randomUUID(), name: 'X', platform: 'android' } },
    });
    expect(res.status).toBe(403);
    expect(res.json.error.code).toBe('ACCOUNT_MISMATCH');
  });

  it('rejects expired tokens and stores only the hash', async () => {
    const token = await tokenFor('user-pair-4', 'e@example.com');
    const desktop = await setupDesktop(token);
    const issued = await call('POST', '/v1/pairing/tokens', { token, keys: desktop.keys, deviceId: desktop.id, body: {} });
    const raw = issued.json.data.token as string;
    expect(issued.json.data.uri).toBe(`bambookit://pair?t=${raw}`);
    expect(Number((await db.get('SELECT COUNT(*) AS n FROM pairing_tokens WHERE token_hash = ?', raw))?.n)).toBe(0);
    await db.run("UPDATE pairing_tokens SET expires_at = '2000-01-01T00:00:00.000Z' WHERE desktop_id = ?", desktop.id);
    const res = await call('POST', '/v1/pairing/claim', { token, body: { token: raw, mobile: { installationId: randomUUID(), name: 'X', platform: 'android' } } });
    expect(res.status).toBe(410);
    expect(res.json.error.code).toBe('PAIRING_TOKEN_EXPIRED');
  });
});

describe('remote control flow', () => {
  it('syncs a session, routes an approval, and delivers commands to the right desktop', async () => {
    const token = await tokenFor('user-flow-1', 'f@example.com');
    const desktop = await setupDesktop(token);
    const { mobileId } = await pairPhone(token, desktop);

    const sync = await call('POST', '/v1/sync', {
      token,
      deviceId: desktop.id,
      keys: desktop.keys,
      body: {
        projects: [{ opencodeProjectId: 'proj_oc_1', name: 'demo', directory: 'C:\\work\\demo', branch: 'main' }],
        sessions: [{ opencodeSessionId: 'ses_oc_1', opencodeProjectId: 'proj_oc_1', directory: 'C:\\work\\demo', title: 'Fix auth', status: 'busy', agent: 'build', model: 'opencode/test', remote: true }],
        parts: [{ opencodeSessionId: 'ses_oc_1', messageId: 'msg_1', partId: 'prt_1', role: 'user', type: 'text', text: 'Fix the auth bug', sortKey: '0001' }],
        diffs: [{ opencodeSessionId: 'ses_oc_1', files: [{ file: 'src/auth.ts', status: 'modified', additions: 3, deletions: 1 }] }],
        approvals: [{ opencodeSessionId: 'ses_oc_1', requestId: 'per_1', permission: 'bash', title: 'npm test', patterns: ['npm test'], status: 'PENDING' }],
      },
    });
    expect(sync.status).toBe(200);

    const sessions = await call('GET', '/v1/sessions', { token });
    expect(sessions.json.data).toHaveLength(1);
    const session = sessions.json.data[0];
    expect(session).toMatchObject({ title: 'Fix auth', status: 'busy', projectName: 'demo', pendingApprovals: 1 });

    expect(session.remote).toBe(true);

    // Chats and diffs are never stored by the API ...
    expect((await db.get('SELECT COUNT(*) AS n FROM session_parts')).n).toBe(0);
    expect((await db.get('SELECT COUNT(*) AS n FROM session_diffs')).n).toBe(0);
    // ... they are read live from the PC, and only while it is online.
    expect((await call('GET', `/v1/sessions/${session.id}/parts`, { token })).json.error.code).toBe('DESKTOP_OFFLINE');
    const stop = await serveDesktop(token, desktop, (kind, params) => {
      expect(params.opencodeSessionId).toBe('ses_oc_1');
      if (kind === 'transcript') return { parts: [{ opencodeSessionId: 'ses_oc_1', messageId: 'msg_1', partId: 'prt_1', role: 'user', type: 'text', text: 'Fix the auth bug', sortKey: '0001' }] };
      if (kind === 'filemap') return { files: [{ path: 'src/auth.ts', actions: ['edited'], firstTurn: 1, lastTurn: 1, additions: 3, deletions: 1, failed: false }] };
      if (kind === 'diagram') return { nodes: [{ id: 'src/auth.ts', label: 'auth.ts' }], edges: [] };
      if (kind === 'tree') return { path: params.path, entries: [{ name: 'auth.ts', path: 'src/auth.ts', type: 'file', size: 10 }] };
      if (kind === 'file') return { path: params.path, content: 'export {}', size: 9 };
      return { files: [{ file: 'src/auth.ts', status: 'modified', additions: 3, deletions: 1 }] };
    });
    expect((await call('GET', `/v1/sessions/${session.id}/parts`, { token })).json.data[0]).toMatchObject({ text: 'Fix the auth bug', sessionId: session.id });
    expect((await call('GET', `/v1/sessions/${session.id}/changes`, { token })).json.data[0]).toMatchObject({ file: 'src/auth.ts', additions: 3 });
    expect((await call('GET', `/v1/sessions/${session.id}/filemap`, { token })).json.data[0]).toMatchObject({ path: 'src/auth.ts', actions: ['edited'] });
    expect((await call('GET', `/v1/sessions/${session.id}/diagram`, { token })).json.data.nodes[0].label).toBe('auth.ts');
    expect((await call('GET', `/v1/sessions/${session.id}/tree?path=src`, { token })).json.data).toMatchObject({ path: 'src', entries: [{ name: 'auth.ts' }] });
    expect((await call('GET', `/v1/sessions/${session.id}/file?path=src/auth.ts`, { token })).json.data.content).toBe('export {}');
    expect((await call('GET', `/v1/sessions/${session.id}/file`, { token })).status).toBe(400);
    stop();

    const approvals = await call('GET', '/v1/approvals?status=PENDING', { token });
    expect(approvals.json.data).toHaveLength(1);
    const respond = await call('POST', `/v1/approvals/${approvals.json.data[0].id}/respond`, { token, deviceId: mobileId, body: { reply: 'once' } });
    expect(respond.status).toBe(202);
    expect(respond.json.data.status).toBe('RESPONDING');
    // Answering twice is rejected.
    expect((await call('POST', `/v1/approvals/${approvals.json.data[0].id}/respond`, { token, body: { reply: 'reject' } })).status).toBe(409);

    const msg = await call('POST', `/v1/sessions/${session.id}/commands`, { token, deviceId: mobileId, body: { type: 'SEND_MESSAGE', payload: { text: 'continue please' } } });
    expect(msg.status).toBe(202);

    const pending = await call('GET', `/v1/devices/${desktop.id}/commands`, { token, deviceId: desktop.id, keys: desktop.keys });
    expect(pending.status).toBe(200);
    expect(pending.json.data.map((c: any) => c.type)).toEqual(['PERMISSION_REPLY', 'SEND_MESSAGE']);
    expect(pending.json.data[0].payload).toEqual({ requestId: 'per_1', reply: 'once' });
    expect(pending.json.data[1].target).toEqual({ opencodeSessionId: 'ses_oc_1', directory: 'C:\\work\\demo' });

    const done = await call('POST', `/v1/commands/${pending.json.data[1].id}/result`, { token, deviceId: desktop.id, keys: desktop.keys, body: { status: 'SUCCEEDED' } });
    expect(done.status).toBe(200);
    expect((await call('GET', `/v1/commands/${pending.json.data[1].id}`, { token })).json.data.status).toBe('SUCCEEDED');

    // OpenCode confirms the permission reply → approval resolved.
    await call('POST', '/v1/sync', {
      token, deviceId: desktop.id, keys: desktop.keys,
      body: { approvals: [{ opencodeSessionId: 'ses_oc_1', requestId: 'per_1', permission: 'bash', status: 'APPROVED', reply: 'once' }], sessions: [{ opencodeSessionId: 'ses_oc_1', opencodeProjectId: 'proj_oc_1', directory: 'C:\\work\\demo', title: 'Fix auth', status: 'idle' }] },
    });
    expect((await call('GET', '/v1/approvals?status=PENDING', { token })).json.data).toHaveLength(0);
    const notes = await call('GET', '/v1/notifications', { token });
    expect(notes.json.data.map((n: any) => n.type).filter((t: string) => t !== 'achievement.unlocked').sort()).toEqual(['approval.required', 'session.completed']);
  });

  it('refuses commands from phones not paired with the desktop', async () => {
    const token = await tokenFor('user-flow-2', 'g@example.com');
    const desktopA = await setupDesktop(token);
    const desktopB = await setupDesktop(token);
    const { mobileId } = await pairPhone(token, desktopB);
    await call('POST', '/v1/sync', { token, deviceId: desktopA.id, keys: desktopA.keys, body: { sessions: [{ opencodeSessionId: 'ses_a', directory: 'C:\\a', title: 'A', status: 'idle' }] } });
    const session = (await call('GET', '/v1/sessions', { token })).json.data[0];
    const res = await call('POST', `/v1/sessions/${session.id}/commands`, { token, deviceId: mobileId, body: { type: 'ABORT', payload: {} } });
    expect(res.status).toBe(403);
    expect(res.json.error.code).toBe('DEVICE_NOT_PAIRED');
  });

  it('isolates users from each other', async () => {
    const alice = await tokenFor('user-iso-a', 'alice@example.com');
    const bob = await tokenFor('user-iso-b', 'bob@example.com');
    const desktop = await setupDesktop(alice);
    await call('POST', '/v1/sync', { token: alice, deviceId: desktop.id, keys: desktop.keys, body: { sessions: [{ opencodeSessionId: 'ses_iso', directory: 'C:\\x', title: 'secret', status: 'busy' }] } });
    const aliceSession = (await call('GET', '/v1/sessions', { token: alice })).json.data[0];

    expect((await call('GET', '/v1/sessions', { token: bob })).json.data).toHaveLength(0);
    expect((await call('GET', `/v1/sessions/${aliceSession.id}`, { token: bob })).status).toBe(404);
    expect((await call('POST', `/v1/sessions/${aliceSession.id}/commands`, { token: bob, body: { type: 'ABORT', payload: {} } })).status).toBe(404);
    expect((await call('GET', `/v1/devices/${desktop.id}`, { token: bob })).status).toBe(404);
    // Bob cannot act as Alice's desktop even with its key.
    expect((await call('POST', '/v1/sync', { token: bob, deviceId: desktop.id, keys: desktop.keys, body: {} })).status).toBe(403);
  });
});

describe('realtime', () => {
  it('replays events after a sequence number', async () => {
    const token = await tokenFor('user-rt-1', 'rt@example.com');
    const desktop = await setupDesktop(token);
    await call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: { sessions: [{ opencodeSessionId: 'ses_rt', directory: 'C:\\rt', title: 'RT', status: 'busy' }] } });

    const controller = new AbortController();
    const res = await app.request('http://localhost/v1/realtime/stream?after=0', { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal });
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    let text = '';
    const decoder = new TextDecoder();
    while (!text.includes('event: session.updated')) {
      const { value, done } = await reader.read();
      if (done) break;
      text += decoder.decode(value);
    }
    controller.abort();
    await reader.cancel().catch(() => {});
    expect(text).toContain('event: ready');
    expect(text).toContain('event: device.registered');
    expect(text).toContain('event: session.updated');
    const ids = [...text.matchAll(/^id: (\d+)$/gm)].map((m) => Number(m[1]));
    expect(ids.length).toBeGreaterThan(0);
    expect([...ids].sort((a, b) => a - b)).toEqual(ids);
  });
});

describe('session sharing', () => {
  it('implements the share protocol and protects writes with the share secret', async () => {
    const created = await call('POST', '/api/share', { body: { sessionID: 'ses_share_1' } });
    expect(created.status).toBe(200);
    const { id, secret, url } = created.json;
    expect(url).toBe(`http://localhost/share/${id}`);
    expect(secret.length).toBeGreaterThan(30);

    const items = [
      { type: 'session', data: { id: 'ses_share_1', title: 'Fix <b>auth</b>' } },
      { type: 'message', data: { id: 'msg_1', role: 'user', time: { created: 1 } } },
      { type: 'part', data: { id: 'prt_1', messageID: 'msg_1', type: 'text', text: 'hello <script>alert(1)</script>' } },
      { type: 'session_diff', data: [{ file: 'src/a.ts', additions: 2, deletions: 1 }] },
    ];
    expect((await call('POST', `/api/share/${id}/sync`, { body: { secret, data: items } })).status).toBe(200);
    // Updating a part replaces it instead of duplicating it.
    await call('POST', `/api/share/${id}/sync`, { body: { secret, data: [{ type: 'part', data: { id: 'prt_1', messageID: 'msg_1', type: 'text', text: 'hello again' } }] } });
    expect((await call('POST', `/api/share/${id}/sync`, { body: { secret: 'wrong', data: items } })).status).toBe(403);

    const data = await call('GET', `/api/share/${id}/data`);
    expect(data.json.filter((i: any) => i.type === 'part')).toHaveLength(1);
    expect(data.json.find((i: any) => i.type === 'part').data.text).toBe('hello again');

    await call('POST', `/api/share/${id}/sync`, { body: { secret, data: [{ type: 'part', data: { id: 'prt_2', messageID: 'msg_1', type: 'text', text: '<script>alert(1)</script>' } }] } });
    const page = await app.request(`http://localhost/share/${id}`);
    const html = await page.text();
    expect(page.status).toBe(200);
    expect(page.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(html).toContain('Fix &lt;b&gt;auth&lt;/b&gt;');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('src/a.ts');

    expect((await call('DELETE', `/api/share/${id}`, { body: { secret: 'wrong' } })).status).toBe(403);
    expect((await call('DELETE', `/api/share/${id}`, { body: { secret } })).status).toBe(200);
    expect((await call('GET', `/api/share/${id}/data`)).status).toBe(404);
  });
});

describe('sessions continue on the PC first', () => {
  it('lets phones chat only in sessions continued on the PC, and start new ones on the PC', async () => {
    const token = await tokenFor('user-tr-1', 'tr@example.com');
    const desktop = await setupDesktop(token);
    const sync = (remote: boolean) =>
      call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: { projects: [{ opencodeProjectId: 'p_tr', name: 'tr', directory: 'C:\tr' }], sessions: [{ opencodeSessionId: 'ses_tr', opencodeProjectId: 'p_tr', directory: 'C:\tr', title: 'TR', status: 'idle', remote }] } });
    await sync(false);
    const session = (await call('GET', '/v1/sessions', { token })).json.data[0];
    expect(session.remote).toBe(false);

    const blocked = await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type: 'SEND_MESSAGE', payload: { text: 'hi' } } });
    expect(blocked.status).toBe(409);
    expect(blocked.json.error.code).toBe('SESSION_NOT_CONTINUED');
    // Reading, stopping and sharing do not need it.
    for (const [type, payload] of [['ABORT', {}], ['SHARE', {}], ['READ_FILE', { path: 'src/a.ts' }]] as const) {
      expect((await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type, payload } })).status).toBe(202);
    }

    await sync(true);
    for (const [type, payload] of [
      ['SEND_MESSAGE', { text: 'continue' }],
      ['REVERT', { messageId: 'msg_1' }],
      ['UNREVERT', {}],
    ] as const) {
      expect((await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type, payload } })).status).toBe(202);
    }
    // Files are view-only remotely.
    expect((await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type: 'WRITE_FILE', payload: { path: 'src/a.ts', content: 'x', baseSha256: null } } })).status).toBe(400);
    expect((await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type: 'REVERT', payload: {} } })).status).toBe(400);

    // New sessions can be started from a phone: the PC creates them in the project's folder.
    const project = (await call('GET', '/v1/projects', { token })).json.data[0];
    const start = await call('POST', `/v1/projects/${project.id}/sessions`, { token, body: { text: 'new', model: { providerID: 'anthropic', modelID: 'claude-x' } } });
    expect(start.status).toBe(202);
    expect(start.json.data.type).toBe('CREATE_SESSION');
    expect(start.json.data.payload).toMatchObject({ text: 'new', model: { providerID: 'anthropic', modelID: 'claude-x' } });
  });

  it('passes live chat parts to open streams without storing them', async () => {
    const token = await tokenFor('user-live-1', 'live@example.com');
    const desktop = await setupDesktop(token);
    await call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: { sessions: [{ opencodeSessionId: 'ses_lv', directory: 'C:\lv', title: 'LV', status: 'busy' }] } });

    const controller = new AbortController();
    const res = await app.request('http://localhost/v1/realtime/stream?client=web', { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal });
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let text = decoder.decode((await reader.read()).value);
    await call('POST', '/v1/sync', {
      token, deviceId: desktop.id, keys: desktop.keys,
      body: { parts: [{ opencodeSessionId: 'ses_lv', messageId: 'm1', partId: 'p1', role: 'assistant', type: 'text', text: 'working on it', sortKey: '1' }] },
    });
    while (!text.includes('event: session.part')) {
      const { value, done } = await reader.read();
      if (done) break;
      text += decoder.decode(value);
    }
    controller.abort();
    await reader.cancel().catch(() => {});
    expect(text).toContain('working on it');
    expect((await db.get("SELECT COUNT(*) AS n FROM events WHERE type = 'session.part'")).n).toBe(0);
    expect((await db.get('SELECT COUNT(*) AS n FROM session_parts')).n).toBe(0);
  });
});

describe('profile, photos and cloud storage isolation', () => {
  it('returns the profile and keeps profile photos per user', async () => {
    const { storage } = await import('../src/services/storage.js');
    const alice = await tokenFor('user-pf-a', 'pfa@example.com');
    const bob = await tokenFor('user-pf-b', 'pfb@example.com');
    const me = (await call('GET', '/v1/me', { token: alice })).json.data;
    expect(me).toMatchObject({ id: 'user-pf-a', email: 'pfa@example.com', cloudStorage: true, devices: 0, projects: 0 });

    expect((await call('POST', '/v1/me/avatar-upload', { token: alice, body: { contentType: 'image/gif', size: 10 } })).status).toBe(400);
    expect((await call('POST', '/v1/me/avatar-upload', { token: alice, body: { contentType: 'image/png', size: 5_000_000 } })).status).toBe(400);
    const up = (await call('POST', '/v1/me/avatar-upload', { token: alice, body: { contentType: 'image/png', size: 4 } })).json.data;
    expect(up.key.startsWith('users/user-pf-a/profile/')).toBe(true);
    expect(up.expiresIn).toBeLessThanOrEqual(300);
    expect((await call('POST', '/v1/me/avatar', { token: alice, body: { key: up.key } })).status).toBe(400); // not uploaded yet
    await storage!.put(up.key, Buffer.from('png!'), 'image/png');
    expect((await call('POST', '/v1/me/avatar', { token: alice, body: { key: up.key } })).status).toBe(200);
    // Another user cannot claim this photo or reach this prefix through a crafted key.
    expect((await call('POST', '/v1/me/avatar', { token: bob, body: { key: up.key } })).status).toBe(403);
    expect((await call('POST', '/v1/me/avatar', { token: bob, body: { key: 'users/user-pf-b/profile/../../user-pf-a/profile/x.png' } })).status).toBe(403);
    expect((await call('GET', '/v1/me', { token: alice })).json.data.avatarStored).toBe(true);
  });

  it('serves history live from the PC, else a cloud copy for 7 days only', async () => {
    const { storage } = await import('../src/services/storage.js');
    const token = await tokenFor('user-hist-1', 'hist@example.com');
    const other = await tokenFor('user-hist-2', 'hist2@example.com');
    const desktop = await setupDesktop(token);
    const desktop2 = await setupDesktop(token);
    await call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: { sessions: [{ opencodeSessionId: 'ses_h', directory: 'C:\\h', title: 'H', status: 'idle' }] } });
    const session = (await call('GET', '/v1/sessions', { token })).json.data[0];

    expect((await call('GET', `/v1/sessions/${session.id}/history`, { token })).json.error.code).toBe('DESKTOP_OFFLINE');
    const stop = await serveDesktop(token, desktop, (kind) => (kind === 'history' ? { prompts: [{ text: 'Fix it' }], changes: [] } : { path: 'a.ts', before: 'x', after: 'y' }));
    const live = (await call('GET', `/v1/sessions/${session.id}/history`, { token })).json.data;
    expect(live).toMatchObject({ source: 'pc', history: { prompts: [{ text: 'Fix it' }], sessionId: session.id } });
    expect((await call('GET', `/v1/sessions/${session.id}/file-versions?path=a.ts`, { token })).json.data).toMatchObject({ before: 'x', after: 'y' });
    stop();

    // Only the session's own PC may upload its copy; size is capped.
    expect((await call('POST', `/v1/sessions/${session.id}/snapshot-upload`, { token, deviceId: desktop2.id, keys: desktop2.keys, body: { size: 10 } })).status).toBe(403);
    expect((await call('POST', `/v1/sessions/${session.id}/snapshot-upload`, { token, deviceId: desktop.id, keys: desktop.keys, body: { size: 50_000_000 } })).status).toBe(400);
    const signed = (await call('POST', `/v1/sessions/${session.id}/snapshot-upload`, { token, deviceId: desktop.id, keys: desktop.keys, body: { size: 10 } })).json.data;
    expect(signed.url).toContain(encodeURIComponent(`users/user-hist-1/sessions/${session.id}.json.gz`));

    const key = `users/user-hist-1/sessions/${session.id}.json.gz`;
    await storage!.put(key, gzipSync(JSON.stringify({ prompts: [{ text: 'Fix it' }] })), 'application/gzip');
    const cloud = (await call('GET', `/v1/sessions/${session.id}/history`, { token })).json.data;
    expect(cloud.source).toBe('cloud');
    expect(cloud.history.prompts[0].text).toBe('Fix it');
    expect((await call('GET', `/v1/sessions/${session.id}/history`, { token: other })).status).toBe(404);

    (storage as any).objects.get(key).lastModified = new Date(Date.now() - 8 * 86_400_000);
    expect((await call('GET', `/v1/sessions/${session.id}/history`, { token })).json.error.code).toBe('DESKTOP_OFFLINE');
    const { sweepExpiredSnapshots } = await import('../src/modules/history.js');
    expect(await sweepExpiredSnapshots()).toBeGreaterThanOrEqual(1);
    expect(await storage!.get(key)).toBeNull();
  });

  it('deletes an account completely and only that account', async () => {
    const { storage } = await import('../src/services/storage.js');
    const alice = await tokenFor('user-del-a', 'dela@example.com');
    const bob = await tokenFor('user-del-b', 'delb@example.com');
    const desktopA = await setupDesktop(alice);
    const desktopB = await setupDesktop(bob);
    await call('POST', '/v1/sync', { token: alice, deviceId: desktopA.id, keys: desktopA.keys, body: { sessions: [{ opencodeSessionId: 'ses_da', directory: 'C:\\a', title: 'A', status: 'idle' }] } });
    await call('POST', '/v1/sync', { token: bob, deviceId: desktopB.id, keys: desktopB.keys, body: { sessions: [{ opencodeSessionId: 'ses_db', directory: 'C:\\b', title: 'B', status: 'idle' }] } });
    await storage!.put('users/user-del-a/profile/avatar-1.png', Buffer.from('a'), 'image/png');
    await storage!.put('users/user-del-b/profile/avatar-1.png', Buffer.from('b'), 'image/png');

    expect((await call('DELETE', '/v1/me', { token: alice, body: {} })).status).toBe(400);

    const realFetch = globalThis.fetch;
    const calls: string[] = [];
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input: any, init?: any) => {
      const url = String(input);
      if (url.includes('/auth/v1/admin/users/')) {
        calls.push(`${init?.method} ${url}`);
        return new Response('{}', { status: 200 });
      }
      return realFetch(input, init);
    });
    try {
      expect((await call('DELETE', '/v1/me', { token: alice, body: { confirm: 'DELETE MY ACCOUNT' } })).status).toBe(200);
    } finally {
      spy.mockRestore();
    }
    expect(calls).toEqual(['DELETE https://test-project.supabase.co/auth/v1/admin/users/user-del-a']);
    expect((await db.get("SELECT COUNT(*) AS n FROM devices WHERE user_id = 'user-del-a'")).n).toBe(0);
    expect((await db.get("SELECT COUNT(*) AS n FROM sessions WHERE user_id = 'user-del-a'")).n).toBe(0);
    expect((await db.get("SELECT COUNT(*) AS n FROM users WHERE id = 'user-del-a'")).n).toBe(0);
    expect(await storage!.get('users/user-del-a/profile/avatar-1.png')).toBeNull();
    expect((await call('GET', '/v1/sessions', { token: bob })).json.data).toHaveLength(1);
    expect(await storage!.get('users/user-del-b/profile/avatar-1.png')).not.toBeNull();
  });
});

describe('agent questions, continue on PC and nicknames', () => {
  it('routes a question to the PC that asked, with the answers, and notifies', async () => {
    const token = await tokenFor('user-q-1', 'q1@example.com');
    const desktop = await setupDesktop(token);
    const { mobileId } = await pairPhone(token, desktop);
    const questions = [
      { header: 'Package manager', question: 'Which package manager should I use?', options: [{ label: 'npm', description: '' }, { label: 'bun', description: 'faster' }] },
      { header: 'Tests', question: 'Which folders?', options: [{ label: 'src', description: '' }, { label: 'test', description: '' }], multiple: true },
    ];
    const ask = (status: string, extra: Record<string, unknown> = {}) =>
      call('POST', '/v1/sync', {
        token, deviceId: desktop.id, keys: desktop.keys,
        body: {
          sessions: [{ opencodeSessionId: 'ses_q', directory: 'C:\q', title: 'Q', status: 'busy' }],
          approvals: [{ opencodeSessionId: 'ses_q', requestId: 'que_1', permission: 'question', title: questions[0].question, patterns: [], status, kind: 'question', questions, ...extra }],
        },
      });
    expect((await ask('PENDING')).status).toBe(200);

    const pending = (await call('GET', '/v1/approvals?status=PENDING', { token })).json.data;
    expect(pending).toHaveLength(1);
    expect(pending[0].kind).toBe('question');
    expect(pending[0].questions[1].multiple).toBe(true);
    const notes = (await call('GET', '/v1/notifications', { token })).json.data;
    expect(notes.map((n: any) => n.type)).toContain('question.asked');

    // A question cannot be "approved"; it needs an answer for every question.
    expect((await call('POST', `/v1/approvals/${pending[0].id}/respond`, { token, body: { reply: 'once' } })).status).toBe(400);
    expect((await call('POST', `/v1/approvals/${pending[0].id}/answer`, { token, body: { answers: [['bun']] } })).status).toBe(400);
    const answered = await call('POST', `/v1/approvals/${pending[0].id}/answer`, { token, deviceId: mobileId, body: { answers: [['bun'], ['src', 'test']] } });
    expect(answered.status).toBe(202);
    expect(answered.json.command.type).toBe('QUESTION_REPLY');
    expect(answered.json.command.payload).toEqual({ requestId: 'que_1', answers: [['bun'], ['src', 'test']] });
    expect((await call('POST', `/v1/approvals/${pending[0].id}/answer`, { token, body: { answers: [['npm'], ['src']] } })).status).toBe(409);

    // The engine confirms → answered.
    await ask('APPROVED', { answers: [['bun'], ['src', 'test']] });
    const done = (await call('GET', `/v1/approvals/${pending[0].id}`, { token })).json.data;
    expect(done.status).toBe('APPROVED');
    expect(done.answers).toEqual([['bun'], ['src', 'test']]);

    // Dismissing a second question sends QUESTION_REJECT.
    await call('POST', '/v1/sync', {
      token, deviceId: desktop.id, keys: desktop.keys,
      body: { approvals: [{ opencodeSessionId: 'ses_q', requestId: 'que_2', permission: 'question', title: 'Proceed?', patterns: [], status: 'PENDING', kind: 'question', questions: [questions[0]] }] },
    });
    const second = (await call('GET', '/v1/approvals?status=PENDING', { token })).json.data[0];
    const dismissed = await call('POST', `/v1/approvals/${second.id}/respond`, { token, body: { reply: 'reject' } });
    expect(dismissed.status).toBe(202);
    expect(dismissed.json.command.type).toBe('QUESTION_REJECT');

    // Another account cannot see or answer it.
    const other = await tokenFor('user-q-2', 'q2@example.com');
    expect((await call('POST', `/v1/approvals/${second.id}/answer`, { token: other, body: { answers: [['npm']] } })).status).toBe(404);
  });

  it('lets a phone ask the PC to continue a session, then chat in it', async () => {
    const token = await tokenFor('user-cp-1', 'cp@example.com');
    const desktop = await setupDesktop(token);
    const sync = (remote: boolean) =>
      call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: { sessions: [{ opencodeSessionId: 'ses_cp', directory: 'C:\cp', title: 'CP', status: 'idle', remote }] } });
    await sync(false);
    const session = (await call('GET', '/v1/sessions', { token })).json.data[0];
    expect((await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type: 'SEND_MESSAGE', payload: { text: 'hi' } } })).status).toBe(409);
    const cont = await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type: 'CONTINUE_ON_PC', payload: {} } });
    expect(cont.status).toBe(202);
    expect(cont.json.data.type).toBe('CONTINUE_ON_PC');
    await sync(true);
    expect((await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type: 'SEND_MESSAGE', payload: { text: 'hi' } } })).status).toBe(202);
  });

  it('keeps a BambooKit nickname over the sign-in name and tells every device', async () => {
    const token = await tokenFor('user-nn-1', 'nick@example.com');
    const before = (await call('GET', '/v1/me', { token })).json.data;
    expect(before.name).toBe('nick');
    expect(before.nickname).toBeNull();

    const bus = await import('../src/realtime/bus.js');
    const seen: string[] = [];
    const off = bus.subscribe(before.id, (e) => { if (e.type === 'profile.updated') seen.push((e.payload as any).name); });
    const set = await call('PATCH', '/v1/me', { token, body: { name: '  Satyam  ' } });
    off();
    expect(set.status).toBe(200);
    expect(set.json.data.name).toBe('Satyam');
    expect(seen).toEqual(['Satyam']);

    // A fresh sign-in token with the provider's name does not overwrite it.
    const again = await tokenFor('user-nn-1', 'nick@example.com');
    expect((await call('GET', '/v1/me', { token: again })).json.data.name).toBe('Satyam');
    expect((await call('PATCH', '/v1/me', { token, body: { name: 'x'.repeat(41) } })).status).toBe(400);
    expect((await call('PATCH', '/v1/me', { token, body: { name: 'bad\u0007name' } })).status).toBe(400);
    // Clearing falls back to the sign-in name.
    expect((await call('PATCH', '/v1/me', { token, body: { name: '' } })).json.data.name).toBe('nick');
  });
});

describe('liking and renaming sessions', () => {
  it('stars a session for this account only and sends renames to the PC', async () => {
    const token = await tokenFor('user-st-1', 'st@example.com');
    const desktop = await setupDesktop(token);
    const sync = () => call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: { sessions: [{ opencodeSessionId: 'ses_st', directory: 'C:\st', title: 'Old', status: 'idle' }] } });
    await sync();
    const session = (await call('GET', '/v1/sessions', { token })).json.data[0];
    expect(session.starred).toBe(false);

    const liked = await call('PATCH', `/v1/sessions/${session.id}`, { token, body: { starred: true } });
    expect(liked.status).toBe(200);
    expect(liked.json.data.starred).toBe(true);
    await sync(); // the PC's next sync does not undo it
    expect((await call('GET', '/v1/sessions?starred=true', { token })).json.data.map((s: any) => s.id)).toEqual([session.id]);
    expect((await call('PATCH', `/v1/sessions/${session.id}`, { token, body: { title: 'x' } })).status).toBe(400);

    const other = await tokenFor('user-st-2', 'st2@example.com');
    expect((await call('PATCH', `/v1/sessions/${session.id}`, { token: other, body: { starred: true } })).status).toBe(404);

    // Renaming works without continuing the session; the PC changes the title.
    const rename = await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type: 'RENAME_SESSION', payload: { title: '  New name ' } } });
    expect(rename.status).toBe(202);
    expect(rename.json.data.payload).toEqual({ title: 'New name' });
    expect((await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type: 'RENAME_SESSION', payload: { title: '' } } })).status).toBe(400);
  });
});

describe('remote control: models, provider keys, todos and request details', () => {
  function encryptionKeyPem() {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    return publicKey.export({ type: 'spki', format: 'pem' }).toString();
  }

  it('sends provider keys only as ciphertext for the PC, and never stores them in the event log', async () => {
    const token = await tokenFor('user-pk-1', 'pk@example.com');
    const keys = desktopKeys();
    const enc = encryptionKeyPem();
    const reg = await call('POST', '/v1/devices/register', { token, keys, body: { kind: 'desktop', name: 'PK PC', platform: 'windows', publicKey: keys.publicPem, encryptionKey: enc } });
    expect(reg.status).toBe(201);
    const desktopId = reg.json.data.id;
    expect(reg.json.data.encryptionKey).toBe(enc);
    // Only RSA keys of 2048 bits or more are accepted.
    const weak = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'pem' }).toString();
    expect((await call('POST', '/v1/devices/register', { token, keys, body: { kind: 'desktop', name: 'PK PC', platform: 'windows', publicKey: keys.publicPem, encryptionKey: weak } })).status).toBe(400);

    const envelope = { alg: 'RSA-OAEP-256+A256GCM', key: 'A'.repeat(344), iv: 'B'.repeat(16), data: 'C'.repeat(64) };
    const set = await call('POST', `/v1/devices/${desktopId}/commands`, { token, body: { type: 'SET_PROVIDER_KEY', payload: { providerID: 'openai', envelope } } });
    expect(set.status).toBe(202);
    // A plain key is not an accepted field.
    expect((await call('POST', `/v1/devices/${desktopId}/commands`, { token, body: { type: 'SET_PROVIDER_KEY', payload: { providerID: 'openai', key: 'plain-text-key' } } })).status).toBe(400);
    expect((await db.get("SELECT COUNT(*) AS n FROM events WHERE type = 'command.created' AND payload LIKE '%RSA-OAEP%'")).n).toBe(0);

    // The PC picks it up from its pending commands, answers, and the ciphertext is deleted.
    const pending = await call('GET', `/v1/devices/${desktopId}/commands`, { token, deviceId: desktopId, keys });
    const cmd = pending.json.data.find((c: any) => c.type === 'SET_PROVIDER_KEY');
    expect(cmd.payload.envelope.alg).toBe('RSA-OAEP-256+A256GCM');
    await call('POST', `/v1/commands/${cmd.id}/result`, { token, deviceId: desktopId, keys, body: { status: 'SUCCEEDED', result: { providerID: 'openai', configured: true } } });
    expect((await db.get('SELECT payload FROM commands WHERE id = ?', cmd.id)).payload).toBe('{}');

    // A PC without an encryption key cannot receive keys.
    const old = await setupDesktop(token);
    const refused = await call('POST', `/v1/devices/${old.id}/commands`, { token, body: { type: 'SET_PROVIDER_KEY', payload: { providerID: 'openai', envelope } } });
    expect(refused.status).toBe(426);
    expect(refused.json.error.code).toBe('DESKTOP_UPDATE_REQUIRED');
    expect(refused.json.error.details.capability).toBe('provider-keys.encrypted');
    // Another account cannot target this PC.
    const other = await tokenFor('user-pk-2', 'pk2@example.com');
    expect((await call('POST', `/v1/devices/${desktopId}/commands`, { token: other, body: { type: 'REMOVE_PROVIDER_KEY', payload: { providerID: 'openai' } } })).status).toBe(404);
  });

  it('relays providers, todos and full request details live from the PC, and passes todo updates without storing them', async () => {
    const token = await tokenFor('user-rc-1', 'rc@example.com');
    const me = (await call('GET', '/v1/me', { token })).json.data;
    const desktop = await setupDesktop(token);
    await call('POST', '/v1/sync', {
      token, deviceId: desktop.id, keys: desktop.keys,
      body: {
        sessions: [{ opencodeSessionId: 'ses_rc', directory: 'C:/rc', title: 'RC', status: 'busy', remote: true }],
        approvals: [{ opencodeSessionId: 'ses_rc', requestId: 'per_rc', permission: 'edit', title: 'src/a.ts', patterns: ['src/a.ts'], status: 'PENDING' }],
      },
    });
    const stop = await serveDesktop(token, desktop, (kind, params) => {
      if (kind === 'providers') return { providers: [{ id: 'anthropic', name: 'Anthropic', configured: true, models: [{ id: 'claude-x', name: 'Claude X' }] }], default: { providerID: 'anthropic', modelID: 'claude-x' } };
      if (kind === 'todos') return { todos: [{ id: 't1', content: 'Fix auth', status: 'in_progress', priority: 'high' }], session: params.opencodeSessionId };
      if (kind === 'approval') return { requestId: params.requestId, diff: '@@ -1 +1 @@\n-x\n+y\n' };
      return null;
    });
    try {
      const providers = await call('GET', `/v1/devices/${desktop.id}/providers`, { token });
      expect(providers.status).toBe(200);
      expect(providers.json.data.providers[0].models[0].id).toBe('claude-x');

      const session = (await call('GET', '/v1/sessions', { token })).json.data[0];
      const todos = await call('GET', `/v1/sessions/${session.id}/todos`, { token });
      expect(todos.json.data.todos[0]).toMatchObject({ content: 'Fix auth', status: 'in_progress' });
      expect(todos.json.data.session).toBe('ses_rc');

      const approval = (await call('GET', '/v1/approvals?status=PENDING', { token })).json.data[0];
      const detail = await call('GET', `/v1/approvals/${approval.id}/detail`, { token });
      expect(detail.json.data.requestId).toBe('per_rc');
      expect(detail.json.data.diff).toContain('+y');

      // SEND_MESSAGE can choose the model and agent.
      const send = await call('POST', `/v1/sessions/${session.id}/commands`, { token, body: { type: 'SEND_MESSAGE', payload: { text: 'go', model: { providerID: 'anthropic', modelID: 'claude-x' }, agent: 'build' } } });
      expect(send.status).toBe(202);
      expect(send.json.data.payload.model.modelID).toBe('claude-x');

      // Todo updates go to open streams only.
      const bus = await import('../src/realtime/bus.js');
      const seen: any[] = [];
      const off = bus.subscribe(me.id, (e) => {
        if (e.type === 'session.todos') seen.push(e.payload);
      });
      await call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: { todos: [{ opencodeSessionId: 'ses_rc', todos: [{ id: 't1', content: 'Fix auth', status: 'completed' }] }] } });
      off();
      expect(seen[0].todos[0].status).toBe('completed');
      expect((await db.get("SELECT COUNT(*) AS n FROM events WHERE type = 'session.todos'")).n).toBe(0);
    } finally {
      stop();
    }
  });
});

describe('complete transcript from the PC', () => {
  it('passes long text and tool details through without cutting them', async () => {
    const token = await tokenFor('user-tx-1', 'tx@example.com');
    const desktop = await setupDesktop(token);
    await call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: { sessions: [{ opencodeSessionId: 'ses_tx', directory: 'C:/tx', title: 'TX', status: 'idle' }] } });
    const long = 'x'.repeat(50_000);
    const stop = await serveDesktop(token, desktop, (kind) =>
      kind === 'transcript'
        ? {
            parts: [
              { opencodeSessionId: 'ses_tx', messageId: 'm1', partId: 'p1', role: 'assistant', type: 'text', text: long, sortKey: '1' },
              {
                opencodeSessionId: 'ses_tx', messageId: 'm1', partId: 'p2', role: 'assistant', type: 'tool', tool: 'bash', toolStatus: 'completed', toolTitle: 'npm test', sortKey: '2',
                input: { command: 'npm test' }, output: 'all 12 tests passed', exitCode: 0, diff: null, time: { start: 1, end: 2 }, secretField: 'dropped',
              },
            ],
          }
        : null,
    );
    try {
      const session = (await call('GET', '/v1/sessions', { token })).json.data.find((s: any) => s.title === 'TX');
      const parts = (await call('GET', `/v1/sessions/${session.id}/parts`, { token })).json.data;
      expect(parts[0].text.length).toBe(50_000);
      expect(parts[1]).toMatchObject({ tool: 'bash', input: { command: 'npm test' }, output: 'all 12 tests passed', exitCode: 0, time: { start: 1, end: 2 } });
      expect(parts[1].secretField).toBeUndefined();
      expect((await db.get('SELECT COUNT(*) AS n FROM session_parts')).n).toBe(0);
    } finally {
      stop();
    }
  });
});

describe('profile statistics, achievements and compatibility', () => {
  it('measures coding time from real work, counts code once per session, and unlocks achievements once', async () => {
    const token = await tokenFor('user-sx-1', 'sx@example.com');
    const desktop = await setupDesktop(token);
    const me = (await call('GET', '/v1/me', { token })).json.data;
    const stats = { filesCreated: 2, filesModified: 3, filesDeleted: 1, filesRenamed: 0, linesAdded: 120, linesDeleted: 30, edits: 7, testsRun: 2, testsPassed: 2, testsFailed: 0, commits: 1, deployments: 0, debugging: true };
    const sync = (status: string, extra: Record<string, unknown> = {}) =>
      call('POST', '/v1/sync', {
        token, deviceId: desktop.id, keys: desktop.keys,
        body: { projects: [{ opencodeProjectId: 'p_sx', name: 'Candy Shooter', directory: 'C:/sx' }], sessions: [{ opencodeSessionId: 'ses_sx', opencodeProjectId: 'p_sx', directory: 'C:/sx', title: 'Fix the crash', status, ...extra }] },
      });
    await sync('idle');
    await sync('busy');
    // Pretend the task started 90 minutes ago (busy_since is set by the API from the status change).
    await db.run("UPDATE sessions SET busy_since = ? WHERE opencode_session_id = 'ses_sx'", new Date(Date.now() - 90 * 60_000).toISOString());
    await sync('idle', { stats });
    // The same totals arriving again must not double-count.
    await sync('idle', { stats });

    const res = await call('GET', '/v1/me/stats', { token });
    expect(res.status).toBe(200);
    const s = res.json.data;
    expect(s.projects).toMatchObject({ total: 1, active: 1, completed: 0, archived: 0 });
    expect(s.projects.list[0]).toMatchObject({ name: 'Candy Shooter', sessions: 1, tasks: 1, filesChanged: 6 });
    expect(s.tasks).toMatchObject({ completed: 1, failed: 0, debugging: 1 });
    expect(s.code).toMatchObject({ filesCreated: 2, filesModified: 3, filesDeleted: 1, linesAdded: 120, linesDeleted: 30, edits: 7, commits: 1 });
    expect(s.codingTime.totalMs).toBeGreaterThanOrEqual(89 * 60_000);
    expect(s.codingTime.totalMs).toBeLessThanOrEqual(91 * 60_000);
    const byId = Object.fromEntries(s.achievements.map((a: any) => [a.id, a]));
    expect(byId['projects-managed']).toMatchObject({ unlocked: true, tier: 'bronze', nextTier: 'silver', progress: 1, target: 5 });
    expect(byId['projects-built'].tier).toBe('bronze');
    expect(byId['code-written']).toMatchObject({ tier: 'bronze', value: 120, target: 1000 });
    expect(byId['files-changed']).toMatchObject({ tier: 'bronze', value: 6 });
    expect(byId['long-sessions']).toMatchObject({ tier: 'bronze', unit: 'hours' });
    expect(byId['code-changes']).toMatchObject({ unlocked: false, tier: null, progress: 7, target: 10 });
    expect(s.achievementSummary.total).toBe(50);

    // Unlocked once: a second refresh adds no rows or notifications.
    const rows = (await db.get('SELECT COUNT(*) AS n FROM user_achievements WHERE user_id = ?', me.id)).n;
    const notesBefore = (await call('GET', '/v1/notifications', { token })).json.data.filter((n: any) => n.type === 'achievement.unlocked').length;
    await call('GET', '/v1/me/achievements', { token });
    expect((await db.get('SELECT COUNT(*) AS n FROM user_achievements WHERE user_id = ?', me.id)).n).toBe(rows);
    const notes = (await call('GET', '/v1/notifications', { token })).json.data.filter((n: any) => n.type === 'achievement.unlocked');
    expect(notes).toHaveLength(notesBefore);

    // A failed task counts as failed, and the project status is the user's.
    await sync('busy');
    await sync('error');
    expect((await call('GET', '/v1/me/stats', { token })).json.data.tasks).toMatchObject({ completed: 1, failed: 1 });
    const project = (await call('GET', '/v1/projects', { token })).json.data[0];
    expect((await call('PATCH', `/v1/projects/${project.id}`, { token, body: { status: 'completed' } })).json.data.status).toBe('completed');
    expect((await call('GET', '/v1/me/stats', { token })).json.data.projects).toMatchObject({ active: 0, completed: 1 });
    const other = await tokenFor('user-sx-2', 'sx2@example.com');
    expect((await call('PATCH', `/v1/projects/${project.id}`, { token: other, body: { status: 'archived' } })).status).toBe(404);
    expect((await call('PATCH', '/v1/me', { token, body: { timeZone: 'Asia/Kolkata' } })).status).toBe(200);
    expect((await call('PATCH', '/v1/me', { token, body: { timeZone: 'Mars/Base' } })).status).toBe(400);
  });

  it('tells clients exactly which desktop version a feature needs, and explains unknown routes', async () => {
    const token = await tokenFor('user-cx-1', 'cx@example.com');
    const keys = desktopKeys();
    const old = await call('POST', '/v1/devices/register', { token, keys, body: { kind: 'desktop', name: 'Old PC', platform: 'windows', appVersion: '1.0.2', publicKey: keys.publicPem } });
    expect(old.json.data.capabilities).toContain('relay.tree');
    expect(old.json.data.capabilities).not.toContain('relay.todos');
    await call('POST', '/v1/sync', { token, deviceId: old.json.data.id, keys, body: { sessions: [{ opencodeSessionId: 'ses_cx', directory: 'C:/cx', title: 'CX', status: 'idle' }] } });
    const session = (await call('GET', '/v1/sessions', { token })).json.data[0];
    const todos = await call('GET', `/v1/sessions/${session.id}/todos`, { token });
    expect(todos.status).toBe(426);
    expect(todos.json.error.code).toBe('DESKTOP_UPDATE_REQUIRED');
    expect(todos.json.error.details).toMatchObject({ currentVersion: '1.0.2', requiredVersion: '1.0.3', capability: 'relay.todos' });
    expect(todos.json.requestId).toBeTruthy();

    const missing = await call('GET', '/v1/definitely-not-a-route', { token });
    expect(missing.status).toBe(404);
    expect(missing.json.error.code).toBe('ROUTE_NOT_FOUND');
    expect(missing.json.error.details).toMatchObject({ method: 'GET', path: '/v1/definitely-not-a-route' });

    const meta = await call('GET', '/v1/meta');
    expect(meta.status).toBe(200);
    expect(meta.json.data.protocol).toBeGreaterThanOrEqual(2);
    expect(meta.json.data.desktopRequirements.providerKeys.since).toBe('1.0.3');
  });
});

describe('tiered achievements', () => {
  const fullStats = {
    filesCreated: 12, filesModified: 40, filesDeleted: 3, filesRenamed: 0, linesAdded: 1500, linesDeleted: 250, edits: 120,
    testsRun: 12, testsPassed: 11, testsFailed: 1, commits: 9, deployments: 1, debugging: true,
    prompts: 1, bugPrompts: 12, toolCalls: 300, terminalCommands: 30, subagentTasks: 6, mcpToolCalls: 4,
    mcpTools: ['github_create_issue', 'github_list_prs', 'linear_search'], agents: ['build', 'explore', 'general'],
    packagesInstalled: 5, branches: 5, merges: 1, pullRequests: 1, cloudDeployments: 1, cleanups: 6, docFiles: 2,
    refactoring: false, review: true, experiment: false, retries: 0, firstTryPass: false, activeSeconds: 300,
  };
  async function syncSession(token: string, desktop: { keys: Keys; id: string }, sessionId: string, stats: unknown) {
    return call('POST', '/v1/sync', {
      token, deviceId: desktop.id, keys: desktop.keys,
      body: {
        projects: [{ opencodeProjectId: 'p_tier', name: 'Tiers', directory: 'C:/tiers' }],
        sessions: [{ opencodeSessionId: sessionId, opencodeProjectId: 'p_tier', directory: 'C:/tiers', title: 'Fix it', status: 'idle', ...(stats ? { stats } : {}) }],
      },
    });
  }
  const notesOf = async (token: string) => (await call('GET', '/v1/notifications', { token })).json.data.filter((n: any) => n.type === 'achievement.unlocked');

  it('returns 50 tiered achievements with backward-compatible fields, unlocks tiers once, and summarises bulk unlocks', async () => {
    const token = await tokenFor('user-tier-1', 'tier1@example.com');
    const desktop = await setupDesktop(token);
    const me = (await call('GET', '/v1/me', { token })).json.data;
    expect((await syncSession(token, desktop, 'ses_t1', fullStats)).status).toBe(200);
    await db.run("UPDATE sessions SET tasks_completed = 1, active_ms = 300000 WHERE opencode_session_id = 'ses_t1'");

    const res = await call('GET', '/v1/me/achievements', { token });
    expect(res.status).toBe(200);
    const list = res.json.data;
    expect(list).toHaveLength(50);
    expect(new Set(list.map((a: any) => a.id)).size).toBe(50);
    for (const a of list) {
      expect(Object.keys(a)).toEqual(expect.arrayContaining(['id', 'emoji', 'title', 'description', 'unit', 'trackable', 'value', 'tiers', 'tier', 'nextTier', 'progress', 'target', 'unlocked', 'unlockedAt']));
      expect(a.tiers.map((t: any) => t.name)).toEqual(['bronze', 'silver', 'gold', 'platinum', 'diamond']);
    }
    const byId = Object.fromEntries(list.map((a: any) => [a.id, a]));
    // Tier thresholds: 1,500 lines is Silver (1K) on the way to Gold (10K).
    expect(byId['code-written']).toMatchObject({ value: 1500, tier: 'silver', nextTier: 'gold', progress: 1500, target: 10_000, unlocked: true });
    expect(byId['code-written'].tiers.map((t: any) => t.unlocked)).toEqual([true, true, false, false, false]);
    expect(byId['code-written'].unlockedAt).toBe(byId['code-written'].tiers[1].unlockedAt);
    expect(byId['code-changes']).toMatchObject({ value: 120, tier: 'silver' });
    expect(byId['commits']).toMatchObject({ value: 9, tier: null, unlocked: false, unlockedAt: null, target: 10 });
    expect(byId['tool-calls']).toMatchObject({ value: 300, tier: 'silver' });
    expect(byId['integrations']).toMatchObject({ value: 2, tier: 'bronze' });
    expect(byId['mcp-tools']).toMatchObject({ value: 3, tier: 'bronze' });
    expect(byId['multi-agent']).toMatchObject({ value: 3, tier: 'bronze' });
    expect(byId['bugs-fixed'].value).toBe(1);
    expect(byId['fast-fix']).toMatchObject({ value: 1, tier: 'bronze' });
    expect(byId['one-shot-fix']).toMatchObject({ value: 1, tier: 'bronze' });
    expect(byId['production-fixes']).toMatchObject({ value: 1, tier: 'bronze' });
    expect(byId['code-reviews'].value).toBe(1);
    expect(byId['tasks-without-retry'].value).toBe(1);
    expect(byId['successful-sessions'].value).toBe(1);
    expect(byId['devices-connected']).toMatchObject({ value: 1, tier: 'bronze' });
    expect(byId['documentation']).toMatchObject({ value: 2, tier: 'bronze' });
    // Untrackable items never show progress.
    for (const id of ['open-source', 'github-stars', 'contributions']) {
      expect(byId[id]).toMatchObject({ trackable: false, reason: 'Needs a GitHub connection — coming later', value: 0, tier: null, unlocked: false });
    }
    expect(byId['code-written'].reason).toBeUndefined();
    // BambooKit Master counts the others with at least Bronze (and itself once it has Bronze).
    const others = list.filter((a: any) => a.id !== 'bambookit-master' && a.tier).length;
    expect(others).toBeGreaterThanOrEqual(10);
    expect(byId['bambookit-master']).toMatchObject({ value: others + 1, tier: others + 1 >= 25 ? 'silver' : 'bronze', target: others + 1 >= 25 ? 35 : 25 });
    const summary = res.json.summary;
    const tiers = list.reduce((n: number, a: any) => n + a.tiers.filter((t: any) => t.unlocked).length, 0);
    const points = list.reduce((n: number, a: any) => n + a.tiers.reduce((m: number, t: any, i: number) => m + (t.unlocked ? i + 1 : 0), 0), 0);
    expect(summary).toMatchObject({ unlocked: others + 1, total: 50, tiersUnlocked: tiers, tiersTotal: 250, points, currentStreak: 1, longestStreak: 1 });

    // Stored per tier; one summary notification instead of one per tier.
    const rows = await db.all<{ achievement: string }>('SELECT achievement FROM user_achievements WHERE user_id = ?', me.id);
    expect(rows.length).toBe(tiers);
    expect(rows.map((r) => r.achievement)).toContain('code-written:silver');
    const notes = await notesOf(token);
    expect(notes.some((n: any) => /^You unlocked \d+ achievement tiers$/.test(n.body))).toBe(true);
    expect(notes.length).toBeLessThanOrEqual(4);

    // Idempotent: refreshing again stores and notifies nothing.
    await call('GET', '/v1/me/achievements', { token });
    await call('GET', '/v1/me/stats', { token });
    expect((await db.get('SELECT COUNT(*) AS n FROM user_achievements WHERE user_id = ?', me.id)).n).toBe(tiers);
    expect(await notesOf(token)).toHaveLength(notes.length);

    // One new tier: its own notification.
    await syncSession(token, desktop, 'ses_t1', { ...fullStats, commits: 10 });
    const after = (await call('GET', '/v1/me/achievements', { token })).json.data.find((a: any) => a.id === 'commits');
    expect(after).toMatchObject({ tier: 'bronze', value: 10, target: 100 });
    const latest = await notesOf(token);
    expect(latest).toHaveLength(notes.length + 1);
    expect(latest.some((n: any) => n.body === '🔀 Commits — Bronze')).toBe(true);

    // Unlocked tiers stay unlocked even if the session is removed on the PC.
    await call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: { removedSessions: ['ses_t1'] } });
    const kept = (await call('GET', '/v1/me/achievements', { token })).json.data.find((a: any) => a.id === 'code-written');
    expect(kept).toMatchObject({ value: 0, tier: 'silver', unlocked: true });
  });

  it('computes streaks and nights in the user time zone', async () => {
    const token = await tokenFor('user-tier-2', 'tier2@example.com');
    await setupDesktop(token);
    const me = (await call('GET', '/v1/me', { token })).json.data;
    const add = (start: string, minutes: number) =>
      db.run(
        'INSERT INTO work_intervals (id, user_id, project_id, session_id, started_at, ended_at, duration_ms, outcome) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        `wrk_${randomUUID()}`, me.id, null, 'ses_none', start, new Date(Date.parse(start) + minutes * 60_000).toISOString(), minutes * 60_000, 'completed',
      );
    // 20:00 UTC is 01:30 the next day in India and 12:00 the same day in Los Angeles.
    await add('2026-01-01T20:00:00.000Z', 10);
    await add('2026-01-02T10:00:00.000Z', 3);
    await add('2026-01-05T10:00:00.000Z', 3);
    await add('2026-01-06T10:00:00.000Z', 3);
    await add('2026-01-07T10:00:00.000Z', 3);
    await add('2026-01-08T10:00:00.000Z', 3);
    const get = async () => {
      const r = (await call('GET', '/v1/me/achievements', { token })).json;
      const byId = Object.fromEntries(r.data.map((a: any) => [a.id, a]));
      return { summary: r.summary, streak: byId['coding-streak'].value, nights: byId['night-coder'].value, speed: byId['speed-builder'].value };
    };
    expect((await call('PATCH', '/v1/me', { token, body: { timeZone: 'UTC' } })).status).toBe(200);
    let r = await get();
    // UTC: Jan 1, 2 (two days) and Jan 5–8 (four days); no work between 22:00 and 05:00.
    expect(r).toMatchObject({ streak: 4, nights: 0, speed: 5 });
    expect(r.summary).toMatchObject({ longestStreak: 4, currentStreak: 0 });
    expect((await call('PATCH', '/v1/me', { token, body: { timeZone: 'Asia/Kolkata' } })).status).toBe(200);
    // India: 01:30 on Jan 2 is the night of Jan 1.
    r = await get();
    expect(r).toMatchObject({ streak: 4, nights: 1 });
    expect((await call('PATCH', '/v1/me', { token, body: { timeZone: 'Pacific/Kiritimati' } })).status).toBe(200);
    // UTC+14: Jan 2 10:00, Jan 3 00:00 and Jan 6–9 00:00 (five nights) → still a four-day streak.
    r = await get();
    expect(r).toMatchObject({ streak: 4, nights: 5 });

    const { streaks, masterValue, mcpServer } = await import('../src/modules/stats.js');
    expect(streaks([1, 2, 3, 7, 8], 9)).toEqual({ longest: 3, current: 2 });
    expect(streaks([1, 2, 3, 7, 8], 8)).toEqual({ longest: 3, current: 2 });
    expect(streaks([5, 1, 2, 3, 2], 10)).toEqual({ longest: 3, current: 0 });
    expect(streaks([], 10)).toEqual({ longest: 0, current: 0 });
    expect(masterValue(9)).toBe(9);
    expect(masterValue(10)).toBe(11);
    expect(masterValue(47)).toBe(48);
    expect(mcpServer('github_create_issue')).toBe('github');
    expect(mcpServer('fetch')).toBe('fetch');
  });

  it('keeps syncing desktops that send only the original statistics, without counting unreported fields', async () => {
    const token = await tokenFor('user-tier-3', 'tier3@example.com');
    const desktop = await setupDesktop(token);
    const old = { filesCreated: 2, filesModified: 3, filesDeleted: 0, filesRenamed: 0, linesAdded: 150, linesDeleted: 5, edits: 12, testsRun: 0, testsPassed: 0, testsFailed: 0, commits: 0, deployments: 0, debugging: true };
    const res = await syncSession(token, desktop, 'ses_old', old);
    expect(res.status).toBe(200);
    expect(res.json.data.rejected).toBeUndefined();
    const stored = JSON.parse((await db.get("SELECT stats FROM sessions WHERE opencode_session_id = 'ses_old'")).stats);
    expect(stored.prompts).toBeUndefined();
    expect(stored.retries).toBeUndefined();
    await db.run("UPDATE sessions SET tasks_completed = 1 WHERE opencode_session_id = 'ses_old'");
    const byId = Object.fromEntries((await call('GET', '/v1/me/achievements', { token })).json.data.map((a: any) => [a.id, a]));
    expect(byId['code-written']).toMatchObject({ value: 150, tier: 'bronze' });
    expect(byId['code-changes']).toMatchObject({ value: 12, tier: 'bronze' });
    expect(byId['bugs-fixed'].value).toBe(1);
    // Retries and prompt counts were never reported, so they prove nothing.
    expect(byId['tasks-without-retry'].value).toBe(0);
    expect(byId['one-shot-fix'].value).toBe(0);
    expect(byId['prompts-sent'].value).toBe(0);

    // Invalid new fields lose only the statistics, never the session.
    const bad = await syncSession(token, desktop, 'ses_bad', { ...old, mcpTools: Array.from({ length: 300 }, (_, i) => `t${i}`) });
    expect(bad.status).toBe(200);
    expect(bad.json.data.rejected?.[0]?.path).toMatch(/^sessions\.0\.stats/);
    expect(await db.get("SELECT id FROM sessions WHERE opencode_session_id = 'ses_bad'")).toBeTruthy();
  });

  it('counts answered approvals, and provider key changes as secure actions', async () => {
    const token = await tokenFor('user-tier-4', 'tier4@example.com');
    const desktop = await setupDesktop(token);
    await syncSession(token, desktop, 'ses_appr', undefined);
    const approvals = ['APPROVED', 'REJECTED', 'APPROVED', 'PENDING'].map((status, i) => ({
      opencodeSessionId: 'ses_appr', requestId: `per_t${i}`, permission: 'bash', title: 'Run', patterns: [], status,
    }));
    const r = await call('POST', '/v1/sync', { token, deviceId: desktop.id, keys: desktop.keys, body: { approvals } });
    expect(r.status).toBe(200);
    const me = (await call('GET', '/v1/me', { token })).json.data;
    await db.run('UPDATE users SET key_changes = 2 WHERE id = ?', me.id);
    const byId = Object.fromEntries((await call('GET', '/v1/me/achievements', { token })).json.data.map((a: any) => [a.id, a]));
    expect(byId['approvals'].value).toBe(3);
    expect(byId['secure-actions']).toMatchObject({ value: 5, tier: 'bronze' });
  });
});

describe('admin panel and Telegram monitoring', () => {
  it('lets only listed admin accounts read service data', async () => {
    const admin = await tokenFor('user-adm-1', 'admin@example.com');
    const regular = await tokenFor('user-adm-2', 'someone@example.com');
    expect((await call('GET', '/v1/me', { token: admin })).json.data.admin).toBe(true);
    expect((await call('GET', '/v1/me', { token: regular })).json.data.admin).toBe(false);

    const denied = await call('GET', '/v1/admin/overview', { token: regular });
    expect(denied.status).toBe(403);
    expect(denied.json.error.code).toBe('NOT_ADMIN');
    expect((await call('GET', '/v1/admin/overview')).status).toBe(401);

    const overview = await call('GET', '/v1/admin/overview', { token: admin });
    expect(overview.status).toBe(200);
    expect(overview.json.data.users.total).toBeGreaterThanOrEqual(2);
    expect(overview.json.data.health).toHaveProperty('uptimeSeconds');
    expect(overview.json.data.service.telegram).toBe(true);
    // Never secrets.
    expect(JSON.stringify(overview.json.data)).not.toContain('test-bot-token');

    const users = await call('GET', '/v1/admin/users?limit=5', { token: admin });
    expect(users.status).toBe(200);
    expect(users.json.data.length).toBeLessThanOrEqual(5);
    expect(users.json.data[0]).toHaveProperty('email');
  });

});

describe('Telegram admin panel', () => {
  type Sent = { method: string; body: any };
  const ADMIN_CHAT = 111;

  /** Captures Telegram API calls (and answers GitHub release lookups) while `fn` runs. */
  async function withTelegram<T>(fn: (sent: Sent[]) => Promise<T>): Promise<T> {
    const tg = await import('../src/services/telegram.js');
    tg.telegramLimits.perChatMs = 0;
    const sent: Sent[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init: any = {}) => {
      const u = String(url);
      if (u.startsWith('https://api.telegram.org/')) {
        const method = u.split('/').pop()!;
        sent.push({ method, body: JSON.parse(init.body) });
        const result = method === 'getWebhookInfo' ? { url: 'https://x/telegram/webhook', pending_update_count: 3, last_error_message: 'Read timeout expired', last_error_date: 1_800_000_000 } : {};
        return Response.json({ ok: true, result });
      }
      if (u.startsWith('https://api.github.com/repos/')) {
        return Response.json({ tag_name: u.includes('android') ? 'v1.0.9' : 'v1.0.5', name: 'r', published_at: null, body: '', html_url: 'https://github.com', assets: [] });
      }
      return realFetch(url, init);
    }) as typeof fetch;
    try {
      return await fn(sent);
    } finally {
      globalThis.fetch = realFetch;
      // The bot token never appears in any request body.
      for (const s of sent) expect(JSON.stringify(s.body)).not.toContain('test-bot-token');
    }
  }

  async function post(update: unknown, secret?: string | null) {
    const { webhookSecret } = await import('../src/services/telegram.js');
    const s = secret === undefined ? webhookSecret : secret;
    return app.request('http://localhost/telegram/webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(s ? { 'X-Telegram-Bot-Api-Secret-Token': s } : {}) },
      body: JSON.stringify(update),
    });
  }
  let updateId = 1000;
  const type = (text: string, chatId = ADMIN_CHAT) => post({ update_id: ++updateId, message: { message_id: updateId, chat: { id: chatId }, from: { id: chatId }, text } });
  const press = (data: string, chatId = ADMIN_CHAT, messageId = 500) =>
    post({ update_id: ++updateId, callback_query: { id: `cq${updateId}`, from: { id: chatId }, data, message: { message_id: messageId, chat: { id: chatId } } } });
  const buttons = (body: any): Array<{ text: string; callback_data: string }> => (body?.reply_markup?.inline_keyboard ?? []).flat();
  const lastOf = (sent: Sent[], method: string) => [...sent].reverse().find((s) => s.method === method)!;
  const userIdOf = async (token: string) => (await call('GET', '/v1/me', { token })).json.data.id as string;

  it('still requires the webhook secret, tells strangers only their chat id and rejects their buttons', async () => {
    await withTelegram(async (sent) => {
      expect((await post({ update_id: 1, message: { chat: { id: ADMIN_CHAT }, text: '/start' } }, null)).status).toBe(403);
      expect((await post({ update_id: 1, message: { chat: { id: ADMIN_CHAT }, text: '/start' } }, 'wrong')).status).toBe(403);
      expect((await post({ update_id: 1, callback_query: { id: 'x', data: 'd', message: { message_id: 1, chat: { id: ADMIN_CHAT } } } }, 'wrong')).status).toBe(403);
      expect(sent).toHaveLength(0);

      expect((await type('📊 Dashboard', 999)).status).toBe(200);
      expect(sent).toHaveLength(1);
      expect(sent[0].body).toEqual({ chat_id: 999, text: expect.stringContaining('Your chat id is 999') });

      // A stranger pressing an old admin button gets nothing but their chat id; nothing is edited.
      await press('d', 999);
      await press('ux:whatever', 999);
      expect(sent.filter((s) => s.method === 'editMessageText')).toHaveLength(0);
      const answers = sent.filter((s) => s.method === 'answerCallbackQuery');
      expect(answers).toHaveLength(2);
      for (const a of answers) {
        expect(a.body.text).toContain('private');
        expect(a.body.text).not.toMatch(/Users|Revenue|Requests/);
      }

      // The admin gets the short reply keyboard and the inline main menu.
      sent.length = 0;
      await type('/start');
      expect(sent.map((s) => s.method)).toEqual(['sendMessage', 'sendMessage']);
      expect(sent[0].body.reply_markup.keyboard.flat().map((b: any) => b.text)).toEqual(['📋 Menu', '📊 Dashboard', '👥 Users', '⚠️ Errors']);
      expect(buttons(sent[1].body).map((b) => b.text)).toEqual(['📊 Dashboard', '👥 Users', '💻 Devices', '🤖 Sessions', '💰 Revenue', '🏆 Achievements', '⚠️ Errors', '🩺 Health', '🔔 Alerts', '⚙️ Settings']);
      for (const s of sent) expect(s.body.chat_id).toBe(ADMIN_CHAT);
    });
  });

  it('navigates with inline buttons by editing the message in place, with Refresh and Menu on every screen', async () => {
    await withTelegram(async (sent) => {
      const { MENU } = await import('../src/services/telegram-ui.js');
      for (const [label, data] of MENU) {
        sent.length = 0;
        expect((await press(data)).status).toBe(200);
        expect(sent.filter((s) => s.method === 'sendMessage')).toHaveLength(0);
        const edit = lastOf(sent, 'editMessageText');
        expect(edit.body).toMatchObject({ chat_id: ADMIN_CHAT, message_id: 500, parse_mode: 'HTML' });
        expect(edit.body.text.length).toBeLessThanOrEqual(4096);
        expect(edit.body.text).toContain(label.split(' ').slice(1).join(' ').replace('Errors', 'errors'));
        expect(edit.body.text).toMatch(/as of \d\d:\d\d · Asia\/Kolkata/);
        const texts = buttons(edit.body).map((b) => b.text);
        expect(texts).toContain('🔄 Refresh');
        expect(texts).toContain('⬅️ Menu');
        for (const b of buttons(edit.body)) expect(Buffer.byteLength(b.callback_data)).toBeLessThanOrEqual(64);
        // answerCallbackQuery always follows.
        expect(sent.at(-1)!.method).toBe('answerCallbackQuery');
      }
      // Menu returns to the main menu; the health screen shows the webhook state.
      await press('hl');
      expect(lastOf(sent, 'editMessageText').body.text).toContain('3 pending updates');
      expect(lastOf(sent, 'editMessageText').body.text).toContain('Read timeout expired');
      await press('m');
      expect(lastOf(sent, 'editMessageText').body.text).toContain('BambooKit admin');
      // Reply-keyboard shortcuts open the same screens as new messages.
      sent.length = 0;
      await type('📊 Dashboard');
      expect(sent[0].method).toBe('sendMessage');
      expect(sent[0].body.text).toContain('Dashboard');
      expect(buttons(sent[0].body).map((b) => b.text)).toContain('🔄 Refresh');
    });
  });

  it('pages through users newest first, 8 per page, and opens a user card', async () => {
    await withTelegram(async (sent) => {
      for (let i = 0; i < 9; i++) await userIdOf(await tokenFor(`user-tgpage-${i}`, `tgpage${i}@example.com`));
      const total = Number((await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM users'))!.n);
      await press('u:0');
      const first = lastOf(sent, 'editMessageText').body;
      const userButtons = buttons(first).filter((b) => b.callback_data.startsWith('uc:'));
      expect(userButtons).toHaveLength(8);
      expect(first.text).toContain(`Users</b> ${total}`);
      expect(buttons(first).map((b) => b.text)).toContain(`1 / ${Math.ceil(total / 8)}`);
      expect(buttons(first).find((b) => b.text === '▶')!.callback_data).toBe('u:1');
      expect(buttons(first).find((b) => b.text === '◀')).toBeUndefined();
      // Newest first: created_at descending.
      const newest = await db.all<{ id: string }>('SELECT id FROM users ORDER BY created_at DESC, id DESC LIMIT 8');
      expect(userButtons.map((b) => b.callback_data.slice(3))).toEqual(newest.map((r) => r.id));

      await press('u:1');
      const second = lastOf(sent, 'editMessageText').body;
      expect(buttons(second).map((b) => b.text)).toContain(`2 / ${Math.ceil(total / 8)}`);
      expect(buttons(second).find((b) => b.text === '◀')!.callback_data).toBe('u:0');
      const secondIds = buttons(second).filter((b) => b.callback_data.startsWith('uc:')).map((b) => b.callback_data);
      expect(secondIds.some((id) => userButtons.some((b) => b.callback_data === id))).toBe(false);

      await press(userButtons[0].callback_data);
      const card = lastOf(sent, 'editMessageText').body;
      expect(card.text).toContain('Plan');
      expect(buttons(card).map((b) => b.text)).toEqual(expect.arrayContaining(['🎁 Pro 7 d', '🎁 Pro 30 d', '🔄 Refresh', '⬅️ Menu']));
    });
  });

  it('finds users by partial email (case-insensitive) or id from typed text and /user', async () => {
    await withTelegram(async (sent) => {
      const token = await tokenFor('user-tgsearch-1', 'Search.Person@Example.com');
      const id = await userIdOf(token);
      await userIdOf(await tokenFor('user-tgsearch-2', 'other.person@example.com'));

      await type('search.PERSON');
      let msg = lastOf(sent, 'sendMessage').body;
      expect(buttons(msg).filter((b) => b.callback_data.startsWith('uc:')).map((b) => b.callback_data)).toEqual([`uc:${id}`]);
      // Admins see full emails inside admin screens.
      expect(msg.text).toContain('Search.Person@Example.com');

      await type('/user person@EXAMPLE');
      msg = lastOf(sent, 'sendMessage').body;
      const ids = buttons(msg).filter((b) => b.callback_data.startsWith('uc:')).map((b) => b.callback_data);
      expect(ids).toEqual(expect.arrayContaining([`uc:${id}`]));
      expect(ids.length).toBeGreaterThanOrEqual(2);

      await type(id);
      expect(buttons(lastOf(sent, 'sendMessage').body).filter((b) => b.callback_data.startsWith('uc:'))[0].callback_data).toBe(`uc:${id}`);

      // At most 8 results.
      await type('@example.com');
      expect(buttons(lastOf(sent, 'sendMessage').body).filter((b) => b.callback_data.startsWith('uc:')).length).toBe(8);

      await type('no-such-user-anywhere');
      expect(lastOf(sent, 'sendMessage').body.text).toContain('No matching users');
    });
  });

  it('grants and removes Pro only after confirmation, emits plan.updated and records admin actions', async () => {
    await withTelegram(async (sent) => {
      const token = await tokenFor('user-tggrant', 'grant.me@gmail.com');
      const id = await userIdOf(token);
      const bus = await import('../src/realtime/bus.js');
      const events: any[] = [];
      const off = bus.subscribe(id, (e) => e.type === 'plan.updated' && events.push(e));
      try {
        await press(`ua:g30:${id}`);
        const ask = lastOf(sent, 'editMessageText').body;
        expect(ask.text).toContain('Grant 30 days of Pro');
        const confirm = buttons(ask).find((b) => b.text === '✅ Confirm')!;
        expect(confirm.callback_data).toMatch(/^ux:/);
        expect(buttons(ask).find((b) => b.text === '✖️ Cancel')!.callback_data).toBe(`uc:${id}`);
        // Asking changes nothing.
        expect(events).toHaveLength(0);
        expect((await call('GET', '/v1/me/plan', { token })).json.data.plan).toBe('free');

        // Another chat cannot use the confirmation.
        await press(confirm.callback_data, 999);
        expect(events).toHaveLength(0);

        const before = Date.now();
        await press(confirm.callback_data);
        expect(lastOf(sent, 'editMessageText').body.text).toContain('Granted 30 days of Pro');
        expect(events).toHaveLength(1);
        expect(events[0].payload).toMatchObject({ plan: 'pro', source: 'admin' });
        const plan = (await call('GET', '/v1/me/plan', { token })).json.data;
        expect(plan).toMatchObject({ plan: 'pro', source: 'admin' });
        expect(Date.parse(plan.proUntil) - before).toBeGreaterThanOrEqual(30 * 86_400_000 - 5000);
        // Not a paid order.
        expect(Number((await db.get<{ n: number }>('SELECT COUNT(*) AS n FROM billing_orders WHERE user_id = ?', id))!.n)).toBe(0);

        // A second tap on the same Confirm does nothing.
        await press(confirm.callback_data);
        expect(lastOf(sent, 'answerCallbackQuery').body.text).toContain('expired');
        expect(events).toHaveLength(1);
        expect((await call('GET', '/v1/me/plan', { token })).json.data.proUntil).toBe(plan.proUntil);

        // Remove Pro (also confirmed).
        await press(`uc:${id}`);
        expect(buttons(lastOf(sent, 'editMessageText').body).map((b) => b.text)).toContain('⛔ Remove Pro');
        await press(`ua:rm:${id}`);
        const rm = buttons(lastOf(sent, 'editMessageText').body).find((b) => b.text === '✅ Confirm')!;
        expect(events).toHaveLength(1);
        await press(rm.callback_data);
        expect(events).toHaveLength(2);
        expect(events[1].payload).toMatchObject({ plan: 'free', source: null });
        expect((await call('GET', '/v1/me/plan', { token })).json.data.plan).toBe('free');

        const actions = await db.all<any>('SELECT actor, action, target_user_id, detail FROM admin_actions WHERE target_user_id = ? ORDER BY created_at', id);
        expect(actions.map((a) => [a.actor, a.action, a.target_user_id])).toEqual([
          ['telegram:111', 'pro.grant', id],
          ['telegram:111', 'pro.remove', id],
        ]);
        expect(JSON.parse(actions[0].detail)).toMatchObject({ days: 30 });
        for (const a of actions) expect(JSON.stringify(a)).not.toContain('test-bot-token');
      } finally {
        off();
      }
    });
  });

  it('counts days in the admin time zone (23:30 IST belongs to that IST day)', async () => {
    const panel = await import('../src/modules/admin-panel.js');
    // 11 Mar 2030 11:30 IST.
    const at = new Date('2030-03-11T06:00:00Z');
    const rows = [
      ['tz-late', '2030-03-10T18:00:00.000Z'], // 10 Mar 23:30 IST → yesterday (IST), same UTC day
      ['tz-early', '2030-03-10T19:00:00.000Z'], // 11 Mar 00:30 IST → today (IST), although 10 Mar in UTC
      ['tz-week', '2030-03-04T19:00:00.000Z'], // 5 Mar 00:30 IST → first of the last 7 IST days (5–11 Mar)
      ['tz-old', '2030-03-04T18:00:00.000Z'], // 4 Mar 23:30 IST → outside
      ['tz-future', '2030-03-11T07:00:00.000Z'], // after `at`
    ];
    for (const [id, created] of rows) await db.run('INSERT INTO users (id, email, created_at, last_seen_at) VALUES (?, ?, ?, ?)', id, `${id}@example.com`, created, created);
    try {
      const d = await panel.dashboard(panel.context(at));
      expect(d.users.new).toMatchObject({ today: 1, yesterday: 1, d7: 3 });
      expect(d.users.dau).toBeGreaterThanOrEqual(1);
      expect(d.tz).toBe('Asia/Kolkata');
      // The daily report for 11 Mar (sent 12 Mar 09:30 IST) counts 11 Mar IST sign-ups; the 23:30 one is 10 Mar.
      const report = await panel.dailyReport(new Date('2030-03-12T04:00:00Z'));
      expect(report).toMatchObject({ day: '2030-03-11', newUsers: 2, newUsersPrev: 1 });
    } finally {
      for (const [id] of rows) await db.run('DELETE FROM users WHERE id = ?', id);
    }
  });

  it('sums revenue from amount_paise for PAID INR orders only', async () => {
    const panel = await import('../src/modules/admin-panel.js');
    const at = new Date('2031-06-15T06:00:00Z'); // 11:30 IST
    const orders: Array<[string, number, string, string, string | null, string]> = [
      ['ord_tg_1', 19_900, 'INR', 'PAID', '2031-06-15T04:00:00.000Z', '2031-06-15T03:59:00.000Z'], // today
      ['ord_tg_2', 199_900, 'INR', 'PAID', '2031-06-13T10:00:00.000Z', '2031-06-13T09:59:00.000Z'], // 7 d
      ['ord_tg_3', 19_900, 'INR', 'PENDING', null, '2031-06-15T02:00:00.000Z'],
      ['ord_tg_4', 19_900, 'INR', 'FAILED', null, '2031-06-14T02:00:00.000Z'],
      ['ord_tg_5', 5_000, 'USD', 'PAID', '2031-06-15T04:30:00.000Z', '2031-06-15T04:29:00.000Z'], // not INR
      ['ord_tg_6', 19_900, 'INR', 'PAID', '2031-06-14T18:20:00.000Z', '2031-06-14T18:19:00.000Z'], // 14 Jun 23:50 IST → yesterday
    ];
    for (const [id, paise, cur, status, paid, created] of orders) {
      await db.run('INSERT INTO billing_orders (id, user_id, product_id, amount_paise, currency, status, created_at, paid_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', id, 'user-tgrev', 'pro-month', paise, cur, status, created, paid);
    }
    try {
      const r = await panel.revenueScreen(panel.context(at));
      expect(r.paise.today).toBe(19_900);
      expect(r.paise.yesterday).toBe(19_900);
      expect(r.paise.d7).toBe(19_900 + 199_900 + 19_900);
      expect(r.paidCount.today).toBe(1);
      expect(r.byStatus).toMatchObject({ PAID: 4, PENDING: 1, FAILED: 1 });
      expect(r.checkouts).toBe(6);
      expect(r.conversion).toBeCloseTo((4 / 6) * 100);
      const { revenueScreenView } = await import('../src/services/telegram-ui.js');
      const view = revenueScreenView(r).text;
      expect(view).toContain('Today ₹199.00 (1)');
      expect(view).toContain('₹2,397.00');
    } finally {
      for (const [id] of orders) await db.run('DELETE FROM billing_orders WHERE id = ?', id);
    }
  });

  it('sends the daily report once per admin-zone day at 09:00, and Send report now works', async () => {
    await withTelegram(async (sent) => {
      const tg = await import('../src/services/telegram.js');
      expect(await tg.checkDailyReport(new Date('2032-01-05T03:00:00Z'))).toBe(false); // 08:30 IST
      expect(sent).toHaveLength(0);
      expect(await tg.checkDailyReport(new Date('2032-01-05T03:40:00Z'))).toBe(true); // 09:10 IST
      expect(sent).toHaveLength(1);
      expect(sent[0].body).toMatchObject({ chat_id: '111', parse_mode: 'HTML' });
      expect(sent[0].body.text).toContain('Daily report');
      expect(sent[0].body.text).toContain('2032-01-04');
      expect(await tg.checkDailyReport(new Date('2032-01-05T10:00:00Z'))).toBe(false);
      // Survives a restart: the date is stored.
      tg.reloadTelegramSettings();
      expect(await tg.checkDailyReport(new Date('2032-01-05T12:00:00Z'))).toBe(false);
      expect(sent).toHaveLength(1);
      expect(await tg.checkDailyReport(new Date('2032-01-06T03:31:00Z'))).toBe(true);
      expect(sent).toHaveLength(2);
      expect(sent[1].body.text).toContain('2032-01-05');

      sent.length = 0;
      await press('sr');
      expect(sent.filter((s) => s.method === 'sendMessage' && s.body.text.includes('Daily report'))).toHaveLength(1);
      expect(lastOf(sent, 'editMessageText').body.text).toContain('Report sent');
      expect(lastOf(sent, 'editMessageText').body.text).toContain('last sent 2032-01-06');
      const logged = await db.get<any>("SELECT actor FROM admin_actions WHERE action = 'report.send'");
      expect(logged.actor).toBe('telegram:111');
    });
  });

  it('persists alert toggles and settings, and masks emails in alerts', async () => {
    await withTelegram(async (sent) => {
      const tg = await import('../src/services/telegram.js');
      expect(await tg.alertEnabled('signup')).toBe(true);
      await press('at:signup');
      expect(lastOf(sent, 'editMessageText').body.text).toContain('🔕 🆕 New sign-ups');
      tg.reloadTelegramSettings();
      expect(await tg.alertEnabled('signup')).toBe(false);
      expect((await db.get<any>("SELECT value FROM telegram_settings WHERE key = 'alert.signup'")).value).toBe('0');

      sent.length = 0;
      await tg.alert('signup', tg.signupAlertText({ email: 'jane.doe@gmail.com', provider: 'google' }));
      expect(sent).toHaveLength(0);
      await press('at:signup');
      tg.reloadTelegramSettings();
      expect(await tg.alertEnabled('signup')).toBe(true);
      sent.length = 0;
      await tg.alert('signup', tg.signupAlertText({ email: 'jane.doe@gmail.com', provider: 'google' }));
      expect(sent).toHaveLength(1);
      expect(sent[0].body.text).toContain('j***@gmail.com');
      expect(sent[0].body.text).not.toContain('jane.doe');
      expect(tg.paymentFailedAlertText({ amount: 199, currency: 'INR', productName: 'Pro', email: 'payer@x.com', environment: 'sandbox', reason: 'dropped by the customer' })).toContain('p***@x.com');

      await press('sp:25');
      tg.reloadTelegramSettings();
      await press('st');
      const settings = lastOf(sent, 'editMessageText').body;
      expect(settings.text).toContain('more than 25 server errors');
      expect(buttons(settings).map((b) => b.text)).toContain('• Spike > 25');
      await press('sp:10');
    });
  });

  it('splits long messages at 4096 characters and escapes HTML', async () => {
    const tg = await import('../src/services/telegram.js');
    const { esc } = await import('../src/services/telegram-ui.js');
    const long = Array.from({ length: 300 }, (_, i) => `<b>line ${i}</b> ${'x'.repeat(40)}`).join('\n');
    const parts = tg.splitMessage(long);
    expect(parts.length).toBeGreaterThan(1);
    for (const p of parts) expect(p.length).toBeLessThanOrEqual(4096);
    expect(parts.join('\n')).toBe(long);
    expect(esc('<script>&"')).toBe('&lt;script&gt;&amp;&quot;');
  });

  it('shows phone app versions reported in X-BK-Client and flags PCs that need an update', async () => {
    await withTelegram(async (sent) => {
      const token = await tokenFor('user-tgdev', 'tgdev@example.com');
      const desktop = await setupDesktop(token); // 1.0.3, latest mocked as 1.0.5
      const { mobileId } = await pairPhone(token, desktop);
      const controller = new AbortController();
      const res = await app.request('http://localhost/v1/realtime/stream', { headers: { Authorization: `Bearer ${token}`, 'X-BK-Device-Id': mobileId, 'X-BK-Client': 'android/1.2.3' }, signal: controller.signal });
      expect(res.status).toBe(200);
      controller.abort();
      await res.body?.cancel().catch(() => {});
      expect((await db.get<any>('SELECT app_version FROM devices WHERE id = ?', mobileId)).app_version).toBe('1.2.3');

      await press('dv');
      const text = lastOf(sent, 'editMessageText').body.text;
      expect(text).toMatch(/Latest release: 1\.0\.5 · \d+ need an update/);
      expect(text).toContain('1.2.3');
      expect(text).toContain('t***@example.com');
    });
  });
});

describe('sync keeps working when one item is invalid', () => {
  it('drops only the bad item, so approvals still reach phones', async () => {
    const token = await tokenFor('user-tol-1', 'tol@example.com');
    const desktop = await setupDesktop(token);
    const res = await call('POST', '/v1/sync', {
      token, deviceId: desktop.id, keys: desktop.keys,
      body: {
        projects: [{ opencodeProjectId: 'p_bad', name: '', directory: '/' }, { opencodeProjectId: 'p_ok', name: 'ok', directory: 'C:/ok' }],
        sessions: [
          { opencodeSessionId: 'ses_tol', directory: 'C:/ok', title: 'T', status: 'busy', stats: { linesAdded: -5 } },
          { opencodeSessionId: 'ses_bad', directory: '', title: 'bad', status: 'busy' },
        ],
        approvals: [{ opencodeSessionId: 'ses_tol', requestId: 'per_tol', permission: 'bash', title: 'Write-Output hi', patterns: ['Write-Output hi'], status: 'PENDING' }],
      },
    });
    expect(res.status).toBe(200);
    expect(res.json.data.rejected.map((r: any) => r.path)).toEqual(expect.arrayContaining(['projects.0.name', 'sessions.0.stats.linesAdded', 'sessions.1.directory']));
    const sessions = (await call('GET', '/v1/sessions', { token })).json.data;
    expect(sessions.map((s: any) => s.title)).toEqual(['T']);
    const pending = (await call('GET', '/v1/approvals?status=PENDING', { token })).json.data;
    expect(pending).toHaveLength(1);
    expect(pending[0].title).toBe('Write-Output hi');
    expect((await call('GET', '/v1/projects', { token })).json.data.map((p: any) => p.name)).toEqual(['ok']);
  });
});

describe('clearing recent activity', () => {
  it('hides earlier activity and removes notifications for this account only', async () => {
    const token = await tokenFor('user-clr-1', 'clr@example.com');
    const other = await tokenFor('user-clr-2', 'clr2@example.com');
    for (const t of [token, other]) {
      const d = await setupDesktop(t);
      await call('POST', '/v1/sync', { token: t, deviceId: d.id, keys: d.keys, body: { sessions: [{ opencodeSessionId: 'ses_clr', directory: 'C:/c', title: 'C', status: 'busy' }], approvals: [{ opencodeSessionId: 'ses_clr', requestId: 'per_clr', permission: 'bash', title: 'ls', patterns: ['ls'], status: 'PENDING' }] } });
    }
    expect((await call('GET', '/v1/activity', { token })).json.data.length).toBeGreaterThan(0);
    expect((await call('GET', '/v1/notifications', { token })).json.data.length).toBeGreaterThan(0);
    const res = await call('DELETE', '/v1/activity', { token });
    expect(res.status).toBe(200);
    expect((await call('GET', '/v1/activity', { token })).json.data).toHaveLength(0);
    expect((await call('GET', '/v1/notifications', { token })).json.data).toHaveLength(0);
    // The other account keeps its activity.
    expect((await call('GET', '/v1/activity', { token: other })).json.data.length).toBeGreaterThan(0);
    expect((await call('GET', '/v1/notifications', { token: other })).json.data.length).toBeGreaterThan(0);
  });
});

describe('plans, limits, payments and rewarded ads', () => {
  const CUTOFF_PASSED = '2100-02-01T00:00:00.000Z';
  const userId = async (token: string) => (await call('GET', '/v1/me', { token })).json.data.id as string;
  const signWebhook = (raw: string, ts = String(Math.floor(Date.now() / 1000))) => ({ ts, sig: createHmac('sha256', 'test-secret').update(ts + raw).digest('base64') });
  const postWebhook = (raw: string, headers: Record<string, string>) =>
    app.request('http://localhost/v1/billing/cashfree/webhook', { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: raw });
  const successEvent = (orderId: string, amount: number) =>
    JSON.stringify({ type: 'PAYMENT_SUCCESS_WEBHOOK', event_time: new Date().toISOString(), data: { order: { order_id: orderId, order_amount: amount, order_currency: 'INR' }, payment: { cf_payment_id: String(Date.now()), payment_status: 'SUCCESS', payment_amount: amount } } });

  /** Mocks Cashfree's API; returns the captured requests. */
  function mockCashfree(orderStatus: Record<string, { order_status: string; order_amount: number }> = {}) {
    const calls: { url: string; method: string; headers: Record<string, string>; body: any }[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init: any = {}) => {
      const u = String(url);
      if (u.startsWith('https://sandbox.cashfree.com/') || u.startsWith('https://api.cashfree.com/')) {
        calls.push({ url: u, method: init.method, headers: init.headers, body: init.body ? JSON.parse(init.body) : null });
        if (init.method === 'POST') {
          const b = JSON.parse(init.body);
          return Response.json({ cf_order_id: 4242, order_id: b.order_id, order_status: 'ACTIVE', payment_session_id: `session_${b.order_id}` });
        }
        const id = decodeURIComponent(u.split('/').pop()!);
        return Response.json({ order_id: id, cf_order_id: 4242, ...(orderStatus[id] ?? { order_status: 'ACTIVE', order_amount: 0 }) });
      }
      return realFetch(url, init);
    }) as typeof fetch;
    return { calls, restore: () => (globalThis.fetch = realFetch) };
  }

  async function capturePlanEvents(token: string) {
    const bus = await import('../src/realtime/bus.js');
    const events: any[] = [];
    const off = bus.subscribe(await userId(token), (e) => {
      if (e.type === 'plan.updated') events.push(e);
    });
    return { events, off };
  }

  it('publishes plans and limits, and starts every account on the free plan', async () => {
    const plans = await call('GET', '/v1/billing/plans');
    expect(plans.status).toBe(200);
    expect(plans.json.data.products).toEqual([
      { id: 'pro-month', name: expect.any(String), amount: 199, currency: 'INR', period: 'month', days: 30 },
      { id: 'pro-year', name: expect.any(String), amount: 1999, currency: 'INR', period: 'year', days: 365 },
    ]);
    expect(plans.json.data.limits).toEqual({ free: { phoneMessagesPerDay: 20, phoneSessionsPerDay: 3, desktops: 1 }, pro: { phoneMessagesPerDay: null, phoneSessionsPerDay: null, desktops: 5 } });
    expect(plans.json.data.payments).toEqual({ configured: true, environment: 'sandbox' });
    expect(plans.json.data.rewards).toEqual({ hours: 24, maxPerDay: 2 });
    expect(JSON.stringify(plans.json)).not.toContain('test-secret');

    const token = await tokenFor('user-bill-free', 'free@example.com');
    expect((await call('GET', '/v1/me/plan')).status).toBe(401);
    const plan = await call('GET', '/v1/me/plan', { token });
    expect(plan.status).toBe(200);
    expect(plan.json.data).toMatchObject({
      plan: 'free',
      source: null,
      proUntil: null,
      ads: true,
      limits: { phoneMessagesPerDay: 20, phoneSessionsPerDay: 3, desktops: 1 },
      usage: { phoneMessagesToday: 0, phoneSessionsToday: 0, desktops: 0 },
      rewards: { todayCount: 0, maxPerDay: 2, hours: 24 },
    });
    // resetsAt is the next midnight in the user's time zone.
    expect(plan.json.data.resetsAt).toMatch(/T00:00:00\.000Z$/);
    await call('PATCH', '/v1/me', { token, body: { timeZone: 'Asia/Kolkata' } });
    expect((await call('GET', '/v1/me/plan', { token })).json.data.resetsAt).toMatch(/T18:30:00\.000Z$/);
    expect((await call('GET', '/v1/me', { token })).json.data).toMatchObject({ plan: 'free', proUntil: null });
  });

  it('limits phone and web chats to 20 and new sessions to 3 a day on the free plan, never PC or approval actions', async () => {
    const token = await tokenFor('user-bill-lim', 'lim@example.com');
    const desktop = await setupDesktop(token);
    const { mobileId } = await pairPhone(token, desktop);
    await call('POST', '/v1/sync', {
      token,
      deviceId: desktop.id,
      keys: desktop.keys,
      body: { projects: [{ opencodeProjectId: 'p_lim', name: 'lim', directory: 'C:/lim' }], sessions: [{ opencodeSessionId: 'ses_lim', opencodeProjectId: 'p_lim', directory: 'C:/lim', title: 'L', status: 'idle', remote: true }] },
    });
    const session = (await call('GET', '/v1/sessions', { token })).json.data[0];
    const send = (deviceId?: string) => call('POST', `/v1/sessions/${session.id}/commands`, { token, deviceId, body: { type: 'SEND_MESSAGE', payload: { text: 'hi' } } });

    for (let i = 0; i < 15; i++) expect((await send(mobileId)).status).toBe(202);
    for (let i = 0; i < 5; i++) expect((await send()).status).toBe(202); // website, same allowance
    // Messages sent from the PC itself never count.
    expect((await send(desktop.id)).status).toBe(202);
    const blocked = await send(mobileId);
    expect(blocked.status).toBe(402);
    expect(blocked.json.error).toMatchObject({
      code: 'PLAN_LIMIT',
      message: 'Free plan limit reached for today.',
      details: { limit: 'phoneMessagesPerDay', max: 20, used: 20, upgradeUrl: 'https://bambookit-web.onrender.com/pricing/' },
    });
    expect(blocked.json.error.details.resetsAt).toBe((await call('GET', '/v1/me/plan', { token })).json.data.resetsAt);
    expect((await send()).status).toBe(402);
    expect((await send(desktop.id)).status).toBe(202);
    // Everything else keeps working.
    for (const [type, payload] of [['ABORT', {}], ['RENAME_SESSION', { title: 'New' }], ['CONTINUE_ON_PC', {}], ['READ_FILE', { path: 'a.ts' }]] as const) {
      expect((await call('POST', `/v1/sessions/${session.id}/commands`, { token, deviceId: mobileId, body: { type, payload } })).status).toBe(202);
    }
    expect((await call('PATCH', `/v1/sessions/${session.id}`, { token, body: { starred: true } })).status).toBe(200);

    const project = (await call('GET', '/v1/projects', { token })).json.data[0];
    const start = () => call('POST', `/v1/projects/${project.id}/sessions`, { token, deviceId: mobileId, body: { text: 'new' } });
    for (let i = 0; i < 3; i++) expect((await start()).status).toBe(202);
    const noMore = await start();
    expect(noMore.status).toBe(402);
    expect(noMore.json.error.details).toMatchObject({ limit: 'phoneSessionsPerDay', max: 3, used: 3 });

    const plan = (await call('GET', '/v1/me/plan', { token })).json.data;
    expect(plan.usage).toEqual({ phoneMessagesToday: 20, phoneSessionsToday: 3, desktops: 1 });
  });

  it('answers 503 for checkout until Cashfree is configured', async () => {
    const { env } = await import('../src/config/env.js');
    const token = await tokenFor('user-bill-503', 'nopay@example.com');
    const saved = env.CASHFREE_APP_ID;
    env.CASHFREE_APP_ID = undefined;
    try {
      const res = await call('POST', '/v1/billing/checkout', { token, body: { productId: 'pro-month' } });
      expect(res.status).toBe(503);
      expect(res.json.error.code).toBe('PAYMENTS_NOT_CONFIGURED');
      expect((await call('GET', '/v1/billing/plans')).json.data.payments.configured).toBe(false);
    } finally {
      env.CASHFREE_APP_ID = saved;
    }
    expect((await call('POST', '/v1/billing/checkout', { token, body: { productId: 'pro-forever' } })).status).toBe(400);
  });

  it('follows the App ID to the right Cashfree server and explains rejections', async () => {
    const { env } = await import('../src/config/env.js');
    const token = await tokenFor('user-bill-env', 'envcheck@example.com');
    const saved = { appId: env.CASHFREE_APP_ID, mode: env.CASHFREE_ENV };
    const urls: string[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (url: any, init: any) => {
      const u = String(url);
      if (!u.includes('cashfree.com')) return realFetch(url, init);
      urls.push(u);
      return Response.json({ message: 'authentication Failed', code: 'request_failed', type: 'authentication_error' }, { status: 401 });
    }) as typeof fetch;
    try {
      env.CASHFREE_ENV = undefined;
      env.CASHFREE_APP_ID = '1234prodkey';
      const prod = await call('POST', '/v1/billing/checkout', { token, body: { productId: 'pro-month' } });
      expect(urls.at(-1)).toBe('https://api.cashfree.com/pg/orders');
      expect(prod.status).toBe(502);
      expect(prod.json.error.message).toContain('authentication Failed');
      expect(prod.json.error.details).toMatchObject({ providerStatus: 401, providerType: 'authentication_error', environment: 'production' });
      expect((await call('GET', '/v1/billing/plans')).json.data.payments.environment).toBe('production');

      env.CASHFREE_APP_ID = 'TEST1234';
      await call('POST', '/v1/billing/checkout', { token, body: { productId: 'pro-month' } });
      expect(urls.at(-1)).toBe('https://sandbox.cashfree.com/pg/orders');

      env.CASHFREE_ENV = 'sandbox';
      env.CASHFREE_APP_ID = '1234prodkey';
      const mismatch = await call('POST', '/v1/billing/checkout', { token, body: { productId: 'pro-month' } });
      expect(mismatch.json.error.details.hint).toContain('production key but CASHFREE_ENV is sandbox');
      expect(JSON.stringify(mismatch.json)).not.toContain('test-secret');
    } finally {
      globalThis.fetch = realFetch;
      env.CASHFREE_APP_ID = saved.appId;
      env.CASHFREE_ENV = saved.mode;
    }
  });

  it('creates Cashfree orders and grants Pro once per verified payment', async () => {
    const token = await tokenFor('user-bill-pay', 'payer.person@gmail.com');
    const uid = await userId(token);
    const plans = await capturePlanEvents(token);
    const billing = await import('../src/modules/billing.js');
    const alerts: any[] = [];
    billing.setPaymentListener((p) => alerts.push(p));
    const cf = mockCashfree();
    try {
      const checkout = await call('POST', '/v1/billing/checkout', { token, body: { productId: 'pro-month' } });
      expect(checkout.status).toBe(200);
      const orderId = checkout.json.data.orderId as string;
      expect(checkout.json.data).toEqual({ orderId, paymentSessionId: `session_${orderId}`, environment: 'sandbox', amount: 199, currency: 'INR', productId: 'pro-month' });
      const req = cf.calls[0];
      expect(req.url).toBe('https://sandbox.cashfree.com/pg/orders');
      expect(req.headers).toMatchObject({ 'x-client-id': 'test-app', 'x-client-secret': 'test-secret', 'x-api-version': '2023-08-01' });
      expect(req.body).toMatchObject({
        order_id: orderId,
        order_amount: 199,
        order_currency: 'INR',
        customer_details: { customer_id: uid.replace(/[^A-Za-z0-9]/g, ''), customer_email: 'payer.person@gmail.com', customer_phone: '9999999999' },
      });
      expect(req.body.order_meta.return_url).toBe('https://bambookit-web.onrender.com/billing/return/?order_id={order_id}');
      expect((await call('GET', `/v1/billing/orders/${orderId}`, { token })).json.data).toMatchObject({ id: orderId, status: 'PENDING', productId: 'pro-month', amount: 199, currency: 'INR', paidAt: null });
      // Orders are private.
      const other = await tokenFor('user-bill-other', 'other@example.com');
      expect((await call('GET', `/v1/billing/orders/${orderId}`, { token: other })).status).toBe(404);

      // Bad or missing signatures, or a changed body, are rejected.
      const raw = successEvent(orderId, 199);
      const { ts, sig } = signWebhook(raw);
      expect((await postWebhook(raw, { 'x-webhook-timestamp': ts, 'x-webhook-signature': 'bad' })).status).toBe(401);
      expect((await postWebhook(raw, {})).status).toBe(401);
      expect((await postWebhook(raw.replace('199', '1'), { 'x-webhook-timestamp': ts, 'x-webhook-signature': sig })).status).toBe(401);
      expect((await call('GET', '/v1/me/plan', { token })).json.data.plan).toBe('free');

      const before = Date.now();
      const ok = await postWebhook(raw, { 'x-webhook-timestamp': ts, 'x-webhook-signature': sig });
      expect(ok.status).toBe(200);
      expect(((await ok.json()) as any).granted).toBe(true);
      const plan = (await call('GET', '/v1/me/plan', { token })).json.data;
      expect(plan).toMatchObject({ plan: 'pro', source: 'payment', ads: false, limits: { phoneMessagesPerDay: null, desktops: 5 } });
      const until = Date.parse(plan.proUntil);
      expect(until - before).toBeGreaterThanOrEqual(30 * 86_400_000 - 5000);
      expect(until - before).toBeLessThanOrEqual(30 * 86_400_000 + 5000);
      expect((await call('GET', '/v1/me', { token })).json.data).toMatchObject({ plan: 'pro', proUntil: plan.proUntil });

      // Cashfree retries webhooks: a duplicate never grants twice.
      const again = await postWebhook(raw, { 'x-webhook-timestamp': ts, 'x-webhook-signature': sig });
      expect(((await again.json()) as any).granted).toBe(false);
      expect((await call('GET', '/v1/me/plan', { token })).json.data.proUntil).toBe(plan.proUntil);
      expect(plans.events).toHaveLength(1);
      expect(plans.events[0].payload).toMatchObject({ plan: 'pro', source: 'payment' });
      expect(alerts).toEqual([expect.objectContaining({ amount: 199, productId: 'pro-month' })]);
      const { paymentAlertText } = await import('../src/services/telegram.js');
      const text = paymentAlertText(alerts[0]);
      expect(text).toContain('199.00');
      expect(text).toContain('p***@gmail.com');
      expect(text).not.toContain('payer.person');

      // A paid amount that does not match the order is not granted.
      const second = await call('POST', '/v1/billing/checkout', { token, body: { productId: 'pro-month' } });
      const wrong = successEvent(second.json.data.orderId, 1);
      const s2 = signWebhook(wrong);
      expect(((await (await postWebhook(wrong, { 'x-webhook-timestamp': s2.ts, 'x-webhook-signature': s2.sig })).json()) as any).granted).toBe(false);
      expect((await call('GET', `/v1/billing/orders/${second.json.data.orderId}`, { token })).json.data.status).toBe('PENDING');
      expect((await call('GET', '/v1/me/plan', { token })).json.data.proUntil).toBe(plan.proUntil);

      const history = await call('GET', '/v1/billing/history', { token });
      expect(history.json.data.map((o: any) => o.id)).toEqual([second.json.data.orderId, orderId]);
      expect(history.json.data[1]).toMatchObject({ status: 'PAID', paidAt: expect.any(String) });
      expect(JSON.stringify(history.json)).not.toContain('session_');

      const admin = await tokenFor('user-bill-adm-view', 'admin@example.com');
      const snap = (await call('GET', '/v1/admin/overview', { token: admin })).json.data.billing;
      expect(snap).toMatchObject({ configured: true, environment: 'sandbox' });
      expect(snap.paidOrders30d).toBeGreaterThanOrEqual(1);
      expect(snap.revenue30d).toBeGreaterThanOrEqual(199);
      expect(snap.activePro).toBeGreaterThanOrEqual(1);
    } finally {
      cf.restore();
      plans.off();
      billing.setPaymentListener(null);
    }
  });

  it('confirms a pending order with Cashfree when the app polls it, and extends existing Pro time', async () => {
    const token = await tokenFor('user-bill-poll', 'poll@example.com');
    const status: Record<string, { order_status: string; order_amount: number }> = {};
    const cf = mockCashfree(status);
    try {
      const checkout = await call('POST', '/v1/billing/checkout', { token, body: { productId: 'pro-year' } });
      const orderId = checkout.json.data.orderId;
      expect((await call('GET', `/v1/billing/orders/${orderId}`, { token })).json.data.status).toBe('PENDING');
      expect(cf.calls.at(-1)!.url).toBe(`https://sandbox.cashfree.com/pg/orders/${orderId}`);

      await db.run('UPDATE users SET pro_until = ?, pro_source = ? WHERE id = ?', new Date(Date.now() + 86_400_000).toISOString(), 'reward', await userId(token));
      status[orderId] = { order_status: 'PAID', order_amount: 1999 };
      const paid = await call('GET', `/v1/billing/orders/${orderId}`, { token });
      expect(paid.json.data).toMatchObject({ status: 'PAID', productId: 'pro-year', amount: 1999 });
      const plan = (await call('GET', '/v1/me/plan', { token })).json.data;
      expect(plan.source).toBe('payment');
      expect(Date.parse(plan.proUntil) - Date.now()).toBeGreaterThan(365 * 86_400_000);
      expect(Date.parse(plan.proUntil) - Date.now()).toBeLessThan(366 * 86_400_000 + 5000);
      // The webhook arriving afterwards changes nothing.
      const raw = successEvent(orderId, 1999);
      const { ts, sig } = signWebhook(raw);
      expect(((await (await postWebhook(raw, { 'x-webhook-timestamp': ts, 'x-webhook-signature': sig })).json()) as any).granted).toBe(false);
      expect((await call('GET', '/v1/me/plan', { token })).json.data.proUntil).toBe(plan.proUntil);
    } finally {
      cf.restore();
    }
  });

  it('grants 24 hours of Pro per verified rewarded ad, at most twice a day', async () => {
    const { setVerifierKeyLoader } = await import('../src/services/admob.js');
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    setVerifierKeyLoader(async () => [{ keyId: 3335741209, base64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64') }]);
    const token = await tokenFor('user-bill-ad', 'ads@example.com');
    const plans = await capturePlanEvents(token);
    try {
      expect((await call('POST', '/v1/rewards/token')).status).toBe(401);
      const issued = await call('POST', '/v1/rewards/token', { token });
      expect(issued.status).toBe(200);
      expect(issued.json.data.userId).toBe(await userId(token));
      const customData = issued.json.data.customData as string;

      const callback = (opts: { tx?: string; unit?: string; data?: string; key?: typeof privateKey; tamper?: boolean } = {}) => {
        const content = `ad_network=5450213213286189855&ad_unit=${opts.unit ?? '8440048550'}&custom_data=${encodeURIComponent(opts.data ?? customData)}&reward_amount=1&reward_item=Pro&timestamp=${Date.now()}&transaction_id=${opts.tx ?? randomBytes(16).toString('hex')}&user_id=${issued.json.data.userId}`;
        const signature = sign('sha256', Buffer.from(content), opts.key ?? privateKey).toString('base64url');
        const query = `${opts.tamper ? content.replace('reward_amount=1', 'reward_amount=9') : content}&signature=${signature}&key_id=3335741209`;
        return app.request(`http://localhost/v1/rewards/admob-ssv?${query}`).then(async (r) => ({ status: r.status, json: (await r.json()) as any }));
      };

      expect((await callback({ tamper: true })).status).toBe(400);
      expect((await callback({ key: generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey })).status).toBe(400);
      expect((await app.request('http://localhost/v1/rewards/admob-ssv?ad_unit=8440048550')).status).toBe(400);
      // Valid signature but not our ad unit or not our token: acknowledged, nothing granted.
      expect((await callback({ unit: '1234567890' })).json.data).toEqual({ granted: false, reason: 'AD_UNIT' });
      expect((await callback({ data: `${customData.split('.')[0]}.AAAAAAAAAAAAAAAAAAAAAA` })).json.data).toEqual({ granted: false, reason: 'CUSTOM_DATA' });
      expect((await call('GET', '/v1/me/plan', { token })).json.data.plan).toBe('free');

      const tx = randomBytes(16).toString('hex');
      const before = Date.now();
      const first = await callback({ tx });
      expect(first).toEqual({ status: 200, json: { data: { granted: true } } });
      let plan = (await call('GET', '/v1/me/plan', { token })).json.data;
      expect(plan).toMatchObject({ plan: 'pro', source: 'reward', ads: false, rewards: { todayCount: 1, maxPerDay: 2, hours: 24 } });
      expect(Date.parse(plan.proUntil) - before).toBeGreaterThanOrEqual(24 * 3600_000 - 5000);
      // Google may deliver the same callback again.
      expect((await callback({ tx })).json.data).toEqual({ granted: false, reason: 'DUPLICATE' });
      expect((await callback()).json.data).toEqual({ granted: true });
      expect((await callback()).json.data).toEqual({ granted: false, reason: 'DAILY_LIMIT' });
      plan = (await call('GET', '/v1/me/plan', { token })).json.data;
      expect(plan.rewards.todayCount).toBe(2);
      expect(Date.parse(plan.proUntil) - before).toBeGreaterThanOrEqual(48 * 3600_000 - 5000);
      expect(Date.parse(plan.proUntil) - before).toBeLessThan(48 * 3600_000 + 5000);
      expect(plans.events).toHaveLength(2);
      expect(plans.events[1].payload.rewards.todayCount).toBe(2);
    } finally {
      plans.off();
      setVerifierKeyLoader(null);
    }
  });

  it('allows one PC on the free plan for new accounts, keeps existing accounts grandfathered, and exempts admins', async () => {
    const registerPc = async (token: string, keys = desktopKeys()) => ({
      keys,
      res: await call('POST', '/v1/devices/register', { token, keys, body: { kind: 'desktop', name: 'PC', platform: 'windows', publicKey: keys.publicPem } }),
    });

    const fresh = await tokenFor('user-bill-new', 'newbie@example.com');
    await db.run('UPDATE users SET created_at = ? WHERE id = ?', CUTOFF_PASSED, await userId(fresh));
    const first = await registerPc(fresh);
    expect(first.res.status).toBe(201);
    const second = await registerPc(fresh);
    expect(second.res.status).toBe(402);
    expect(second.res.json.error).toMatchObject({ code: 'PLAN_LIMIT', details: { limit: 'desktops', max: 1, used: 1, upgradeUrl: 'https://bambookit-web.onrender.com/pricing/' } });
    // The same PC can always register again (updates, restarts).
    expect((await registerPc(fresh, first.keys)).res.status).toBe(200);
    // Pro allows more PCs.
    await db.run('UPDATE users SET pro_until = ?, pro_source = ? WHERE id = ?', new Date(Date.now() + 86_400_000).toISOString(), 'payment', await userId(fresh));
    expect((await registerPc(fresh)).res.status).toBe(201);

    const old = await tokenFor('user-bill-old', 'oldtimer@example.com');
    await userId(old);
    expect((await registerPc(old)).res.status).toBe(201);
    expect((await registerPc(old)).res.status).toBe(201);

    const admin = await tokenFor('user-bill-admin', 'admin@example.com');
    await db.run('UPDATE users SET created_at = ? WHERE id = ?', CUTOFF_PASSED, await userId(admin));
    const plan = (await call('GET', '/v1/me/plan', { token: admin })).json.data;
    expect(plan).toMatchObject({ plan: 'pro', source: 'admin', ads: false, limits: { phoneMessagesPerDay: null, phoneSessionsPerDay: null } });
    const pcs = [await registerPc(admin), await registerPc(admin)];
    expect(pcs.map((p) => p.res.status)).toEqual([201, 201]);
    const desktop = { keys: pcs[0].keys, id: pcs[0].res.json.data.id as string };
    await call('POST', '/v1/sync', { token: admin, deviceId: desktop.id, keys: desktop.keys, body: { sessions: [{ opencodeSessionId: 'ses_adm', directory: 'C:/a', title: 'A', status: 'idle', remote: true }] } });
    const session = (await call('GET', `/v1/sessions?deviceId=${desktop.id}`, { token: admin })).json.data[0];
    for (let i = 0; i < 25; i++) {
      expect((await call('POST', `/v1/sessions/${session.id}/commands`, { token: admin, body: { type: 'SEND_MESSAGE', payload: { text: 'x' } } })).status).toBe(202);
    }
  });
});
