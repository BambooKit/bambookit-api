import { beforeAll, describe, expect, it, vi } from 'vitest';
import { gzipSync } from 'node:zlib';
import { generateKeyPairSync, sign, createHash, randomUUID } from 'node:crypto';
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

let app: typeof import('../src/app.js').app;
let db: typeof import('../src/db/database.js').db;

beforeAll(async () => {
  app = (await import('../src/app.js')).app;
  db = (await import('../src/db/database.js')).db;
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
    body: { kind: 'desktop', name: 'Test PC', platform: 'windows', appVersion: '1.0.0', publicKey: keys.publicPem },
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
    expect(notes.json.data.map((n: any) => n.type).sort()).toEqual(['approval.required', 'session.completed']);
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
  it('lets phones chat only in sessions continued on the PC, and starts no sessions remotely', async () => {
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

    const project = (await call('GET', '/v1/projects', { token })).json.data[0];
    const start = await call('POST', `/v1/projects/${project.id}/sessions`, { token, body: { text: 'new' } });
    expect(start.status).toBe(403);
    expect(start.json.error.code).toBe('START_ON_PC');
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
