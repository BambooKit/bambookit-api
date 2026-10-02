import { Hono } from 'hono';
import { VERSION } from '../config/env.js';
import { db, parseJson } from '../db/database.js';
import { requireUser, type AppEnv, type DeviceRow } from '../middleware/auth.js';
import { isConnected, streamCount, webCount } from '../realtime/bus.js';
import { isDeviceOnline } from './serializers.js';

/**
 * Live architecture graph — the single shared model that BambooKit Web, Desktop and Android draw.
 * Every value is derived from stored state (devices, projects, sessions, parts, diffs, approvals,
 * engine reports from the desktop) and live presence. Nothing is invented: when there is no
 * activity, nodes report the real idle / offline / unknown state.
 */
export type NodeStatus = 'online' | 'offline' | 'active' | 'idle' | 'warning' | 'error' | 'unknown';

export interface ArchNode {
  id: string;
  kind: string;
  label: string;
  status: NodeStatus;
  detail: string;
  /** Layer index (top → bottom) so every client can lay the graph out consistently. */
  layer: number;
  metrics?: Record<string, string | number | boolean | null>;
  /** What a client should open when the node is selected. */
  link?: { type: 'account' | 'device' | 'project' | 'session' | 'changes' | 'approvals' | 'devices' | 'api'; id?: string };
}

export interface ArchEdge {
  from: string;
  to: string;
  state: 'live' | 'idle' | 'down';
}

const TEST_COMMAND = /\b(npm|pnpm|yarn|bun)\s+(run\s+)?test\b|\bvitest\b|\bjest\b|\bpytest\b|\bgo\s+test\b|\bcargo\s+test\b|\bgradlew?\b.*\btest|\bmvn\b.*\btest\b|\bdotnet\s+test\b|\bplaywright\s+test\b/i;

export const architectureRouter = new Hono<AppEnv>();
architectureRouter.use('*', requireUser);

architectureRouter.get('/', async (c) => {
  const user = c.get('user');
  const userRow = await db.get('SELECT * FROM users WHERE id = ?', user.id);
  const devices = await db.all<DeviceRow>('SELECT * FROM devices WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at', user.id);
  const desktops = devices.filter((d) => d.kind === 'desktop');
  const mobiles = devices.filter((d) => d.kind === 'mobile');
  const links = await db.all('SELECT desktop_id, mobile_id FROM device_links WHERE user_id = ?', user.id);

  // Focus: requested desktop, else an online one, else the most recently seen.
  const requested = c.req.query('desktopId');
  const focus =
    desktops.find((d) => d.id === requested) ??
    desktops.find((d) => isConnected(d.id)) ??
    [...desktops].sort((a, b) => String(b.last_seen_at ?? '').localeCompare(String(a.last_seen_at ?? '')))[0];
  const focusOnline = !!focus && isConnected(focus.id);

  const nodes: ArchNode[] = [];
  const edges: ArchEdge[] = [];
  const edge = (from: string, to: string, live: boolean, idle = false) => edges.push({ from, to, state: live ? 'live' : idle ? 'idle' : 'down' });

  // ---------------------------------------------------------------- layer 0-2: account, clients, API
  nodes.push({ id: 'account', kind: 'account', label: user.email ?? 'Account', status: 'online', detail: `${devices.length} device${devices.length === 1 ? '' : 's'} on this account`, layer: 0, link: { type: 'account' } });

  const web = webCount(user.id);
  nodes.push({ id: 'web', kind: 'web', label: 'BambooKit Web', status: web > 0 ? 'online' : 'offline', detail: web > 0 ? `${web} browser session${web === 1 ? '' : 's'} connected` : 'No browser connected', layer: 1, metrics: { connections: web } });
  edge('account', 'web', web > 0, true);

  if (mobiles.length === 0) {
    nodes.push({ id: 'android', kind: 'android', label: 'BambooKit Android', status: 'offline', detail: 'No phone registered', layer: 1, link: { type: 'devices' } });
    edge('account', 'android', false, true);
  }
  for (const m of mobiles) {
    const online = isDeviceOnline(m);
    const pairedTo = links.filter((l: any) => l.mobile_id === m.id).length;
    nodes.push({
      id: `android:${m.id}`, kind: 'android', label: m.name, status: online ? 'online' : 'offline',
      detail: `${online ? 'Connected' : 'Offline'} · paired with ${pairedTo} PC${pairedTo === 1 ? '' : 's'}${m.last_seen_at ? ` · last seen ${m.last_seen_at}` : ''}`,
      layer: 1, metrics: { online, pairedTo, lastSeenAt: m.last_seen_at }, link: { type: 'device', id: m.id },
    });
    edge('account', `android:${m.id}`, online, true);
  }

  if (desktops.length === 0) {
    nodes.push({ id: 'desktop', kind: 'desktop', label: 'BambooKit Desktop', status: 'offline', detail: 'No PC registered', layer: 1, link: { type: 'devices' } });
    edge('account', 'desktop', false, true);
  }
  for (const d of desktops) {
    const online = isConnected(d.id);
    nodes.push({
      id: `desktop:${d.id}`, kind: 'desktop', label: d.name, status: online ? 'online' : 'offline',
      detail: `${online ? 'Connected' : 'Offline'}${d.app_version ? ` · BambooKit Desktop ${d.app_version}` : ''}${!online && d.last_seen_at ? ` · last seen ${d.last_seen_at}` : ''}`,
      layer: 1, metrics: { online, focus: d.id === focus?.id, lastSeenAt: d.last_seen_at }, link: { type: 'device', id: d.id },
    });
    edge('account', `desktop:${d.id}`, online, true);
  }

  const streams = streamCount(user.id, devices.map((d) => d.id));
  nodes.push({ id: 'api', kind: 'api', label: 'BambooKit API', status: 'online', detail: `v${VERSION} · ${db.dialect} · ${streams} live stream${streams === 1 ? '' : 's'}`, layer: 2, metrics: { version: VERSION, database: db.dialect, streams }, link: { type: 'api' } });
  for (const n of nodes.filter((n) => n.layer === 1)) edge(n.id, 'api', n.status === 'online');

  const pendingTotal = Number((await db.get("SELECT COUNT(*) AS n FROM approvals WHERE user_id = ? AND status IN ('PENDING','RESPONDING')", user.id))?.n ?? 0);

  if (!focus) {
    return c.json({ data: { generatedAt: new Date().toISOString(), focusDesktopId: null, nodes, edges, pendingApprovals: pendingTotal } });
  }

  // ---------------------------------------------------------------- layer 3+: the focused PC's engine and work
  const engineRow = await db.get('SELECT * FROM device_state WHERE device_id = ?', focus.id);
  const engine = parseJson<any>(engineRow?.state, null);
  const engineFresh = !!engineRow && Date.now() - Date.parse(engineRow.updated_at) < 10 * 60_000;
  nodes.push({
    id: 'engine', kind: 'engine', label: 'Agent engine', layer: 3,
    status: !focusOnline ? 'offline' : engine ? 'online' : 'unknown',
    detail: !focusOnline ? `${focus.name} is offline` : engine ? `Running on ${focus.name}${engine.version ? ` · engine ${engine.version}` : ''}` : 'Waiting for the desktop to report engine state',
    metrics: { version: engine?.version ?? null, reportedAt: engineRow?.updated_at ?? null },
    link: { type: 'device', id: focus.id },
  });
  edge(`desktop:${focus.id}`, 'engine', focusOnline);
  edge('api', `desktop:${focus.id}`, focusOnline);

  const active = await db.all(
    `SELECT s.*, p.name AS project_name FROM sessions s LEFT JOIN projects p ON p.id = s.project_id
     WHERE s.device_id = ? AND s.status IN ('busy','retry') AND s.parent_opencode_session_id IS NULL ORDER BY s.updated_at DESC`,
    focus.id,
  );
  const latest = await db.get(
    `SELECT s.*, p.name AS project_name FROM sessions s LEFT JOIN projects p ON p.id = s.project_id
     WHERE s.device_id = ? AND s.parent_opencode_session_id IS NULL ORDER BY s.updated_at DESC LIMIT 1`,
    focus.id,
  );
  const session = active[0] ?? latest;
  const totalSessions = Number((await db.get('SELECT COUNT(*) AS n FROM sessions WHERE device_id = ? AND parent_opencode_session_id IS NULL', focus.id))?.n ?? 0);

  nodes.push({
    id: 'sessions', kind: 'sessions', label: 'Sessions', layer: 4,
    status: active.length ? 'active' : totalSessions ? 'idle' : 'unknown',
    detail: active.length ? `${active.length} working: ${active.map((s: any) => s.title).slice(0, 3).join(', ')}` : `${totalSessions} session${totalSessions === 1 ? '' : 's'}, none working`,
    metrics: { active: active.length, total: totalSessions, opencodeSessionId: session?.opencode_session_id ?? null, directory: session?.directory ?? null },
    link: session ? { type: 'session', id: session.id } : undefined,
  });
  edge('engine', 'sessions', focusOnline && active.length > 0, focusOnline);

  if (!session) {
    return c.json({ data: { generatedAt: new Date().toISOString(), focusDesktopId: focus.id, nodes, edges, pendingApprovals: pendingTotal } });
  }

  const sessionStatus: NodeStatus = session.status === 'busy' ? 'active' : session.status === 'retry' ? 'warning' : session.status === 'error' ? 'error' : 'idle';
  const working = session.status === 'busy' || session.status === 'retry';
  nodes.push({
    id: 'agent', kind: 'agent', label: session.agent ? `Agent · ${session.agent}` : 'Agent', layer: 5, status: sessionStatus,
    detail: [session.title, session.model ? `model ${String(session.model).replace(/^opencode\//, 'BambooKit/')}` : null, session.current_action ?? (working ? 'Working' : 'Idle'), session.status_message].filter(Boolean).join(' · '),
    metrics: { sessionId: session.id, opencodeSessionId: session.opencode_session_id, directory: session.directory, status: session.status, model: session.model, currentAction: session.current_action },
    link: { type: 'session', id: session.id },
  });
  edge('sessions', 'agent', working);

  // Tool activity in this session.
  const tools = await db.all('SELECT tool, tool_status, tool_title, updated_at FROM session_parts WHERE session_id = ? AND type = ? ORDER BY sort_key DESC LIMIT 40', session.id, 'tool');
  const runningTool = tools.find((t: any) => t.tool_status === 'running' || t.tool_status === 'pending');
  const lastTool = runningTool ?? tools[0];
  nodes.push({
    id: 'tools', kind: 'tools', label: 'Tools', layer: 6,
    status: runningTool ? 'active' : lastTool?.tool_status === 'error' ? 'error' : tools.length ? 'idle' : 'unknown',
    detail: lastTool ? `${runningTool ? 'Running' : 'Last'}: ${lastTool.tool} ${lastTool.tool_title ?? ''}`.trim() : 'No tool calls in this session',
    metrics: { calls: tools.length, last: lastTool?.tool ?? null },
    link: { type: 'session', id: session.id },
  });
  edge('agent', 'tools', !!runningTool, true);

  const mcp: Array<{ name: string; status: string }> = engine?.mcp ?? [];
  const mcpUp = mcp.filter((m) => m.status === 'connected').length;
  const mcpFailed = mcp.filter((m) => m.status === 'failed' || m.status === 'error').length;
  nodes.push({
    id: 'mcp', kind: 'mcp', label: 'MCP', layer: 6,
    status: !engine ? 'unknown' : mcp.length === 0 ? 'idle' : mcpFailed ? 'warning' : 'online',
    detail: !engine ? 'Not reported yet' : mcp.length === 0 ? 'No MCP servers configured' : mcp.map((m) => `${m.name}: ${m.status}`).join(', '),
    metrics: { servers: mcp.length, connected: mcpUp, failed: mcpFailed },
  });
  edge('agent', 'mcp', mcpUp > 0, true);

  const providers: Array<{ id: string; name: string }> = engine?.providers ?? [];
  nodes.push({
    id: 'providers', kind: 'providers', label: 'Model providers', layer: 6,
    status: !engine ? 'unknown' : providers.length ? 'online' : 'warning',
    detail: !engine ? 'Not reported yet' : providers.length ? providers.map((p) => p.name).slice(0, 6).join(', ') : 'No provider connected',
    metrics: { connected: providers.length, model: session.model },
  });
  edge('agent', 'providers', working, true);

  const project = session.project_id ? await db.get('SELECT * FROM projects WHERE id = ?', session.project_id) : null;
  nodes.push({
    id: 'project', kind: 'project', label: project?.name ?? session.directory.split(/[\\/]/).pop() ?? 'Project', layer: 7,
    status: working ? 'active' : 'idle',
    detail: `${project?.directory ?? session.directory}${project?.branch ? ` · ${project.branch}` : ''}`,
    metrics: { directory: project?.directory ?? session.directory, branch: project?.branch ?? null },
    link: project ? { type: 'project', id: project.id } : { type: 'session', id: session.id },
  });
  edge('tools', 'project', !!runningTool, true);

  const diffs = await db.all('SELECT file, additions, deletions FROM session_diffs WHERE session_id = ?', session.id);
  const added = diffs.reduce((n: number, d: any) => n + Number(d.additions), 0);
  const removed = diffs.reduce((n: number, d: any) => n + Number(d.deletions), 0);
  const editing = runningTool && ['edit', 'write', 'multiedit', 'apply_patch', 'patch'].includes(runningTool.tool);
  nodes.push({
    id: 'files', kind: 'files', label: 'Files', layer: 8,
    status: editing ? 'active' : diffs.length ? 'idle' : 'unknown',
    detail: diffs.length ? `${diffs.length} changed · +${added} −${removed}` : 'No file changes in this session',
    metrics: { changed: diffs.length, additions: added, deletions: removed },
    link: { type: 'changes', id: session.id },
  });
  edge('project', 'files', !!editing, true);

  nodes.push({
    id: 'git', kind: 'git', label: 'Git', layer: 8,
    status: project?.branch ? 'online' : 'unknown',
    detail: project?.branch ? `Branch ${project.branch}${diffs.length ? ` · ${diffs.length} file${diffs.length === 1 ? '' : 's'} changed in this session` : ''}` : 'Not a git repository (or not reported)',
    metrics: { branch: project?.branch ?? null, changed: diffs.length },
    link: { type: 'changes', id: session.id },
  });
  edge('project', 'git', false, true);

  const terminals: Array<{ id: string; title?: string; status?: string }> = engine?.terminals ?? [];
  const runningShell = runningTool && runningTool.tool === 'bash';
  nodes.push({
    id: 'terminal', kind: 'terminal', label: 'Terminal', layer: 8,
    status: runningShell || terminals.some((t) => t.status === 'running') ? 'active' : terminals.length ? 'idle' : 'unknown',
    detail: runningShell ? `Running: ${runningTool.tool_title ?? 'command'}` : terminals.length ? `${terminals.length} terminal${terminals.length === 1 ? '' : 's'} open` : engine ? 'No terminal open' : 'Not reported yet',
    metrics: { terminals: terminals.length, running: !!runningShell },
  });
  edge('project', 'terminal', !!runningShell, true);

  const testRun = tools.find((t: any) => t.tool === 'bash' && TEST_COMMAND.test(String(t.tool_title ?? '')));
  nodes.push({
    id: 'tests', kind: 'tests', label: 'Tests', layer: 9,
    status: !testRun ? 'unknown' : testRun.tool_status === 'running' || testRun.tool_status === 'pending' ? 'active' : testRun.tool_status === 'error' ? 'error' : 'online',
    detail: testRun ? `${testRun.tool_title} · ${testRun.tool_status === 'completed' ? 'finished' : testRun.tool_status}` : 'No test run in this session',
    metrics: { command: testRun?.tool_title ?? null, status: testRun?.tool_status ?? null },
    link: { type: 'session', id: session.id },
  });
  edge('files', 'tests', !!testRun && testRun.tool_status === 'running', true);

  const pendingHere = Number((await db.get("SELECT COUNT(*) AS n FROM approvals WHERE session_id = ? AND status IN ('PENDING','RESPONDING')", session.id))?.n ?? 0);
  nodes.push({
    id: 'approvals', kind: 'approvals', label: 'Approvals', layer: 5,
    status: pendingTotal > 0 ? 'warning' : 'idle',
    detail: pendingTotal > 0 ? `${pendingTotal} waiting for you${pendingHere ? ` (${pendingHere} in this session)` : ''}` : 'Nothing waiting',
    metrics: { pending: pendingTotal, inSession: pendingHere },
    link: { type: 'approvals' },
  });
  edge('agent', 'approvals', pendingHere > 0, true);

  return c.json({
    data: {
      generatedAt: new Date().toISOString(),
      focusDesktopId: focus.id,
      focusSessionId: session.id,
      nodes,
      edges,
      pendingApprovals: pendingTotal,
    },
  });
});
