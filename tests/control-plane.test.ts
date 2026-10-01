import { beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign, createHash, randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';

process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = ':memory:';
process.env.SUPABASE_URL = 'https://test-project.supabase.co';
process.env.SUPABASE_JWT_SECRET = 'test-jwt-secret-for-unit-tests-only-0123456789';
process.env.LOG_LEVEL = 'error';
process.env.FIREBASE_PROJECT_ID = 'test-firebase-project';

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
    expect(db.prepare('SELECT COUNT(*) AS n FROM pairing_tokens WHERE token_hash = ?').get(raw)).toMatchObject({ n: 0 });
    db.prepare("UPDATE pairing_tokens SET expires_at = '2000-01-01T00:00:00.000Z' WHERE desktop_id = ?").run(desktop.id);
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
        sessions: [{ opencodeSessionId: 'ses_oc_1', opencodeProjectId: 'proj_oc_1', directory: 'C:\\work\\demo', title: 'Fix auth', status: 'busy', agent: 'build', model: 'opencode/test' }],
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

    expect((await call('GET', `/v1/sessions/${session.id}/parts`, { token })).json.data[0].text).toBe('Fix the auth bug');
    expect((await call('GET', `/v1/sessions/${session.id}/changes`, { token })).json.data[0]).toMatchObject({ file: 'src/auth.ts', additions: 3 });

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
