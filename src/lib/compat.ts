import { HttpError } from './http.js';

/**
 * Versions and capabilities shared by the API, BambooKit Desktop, Android and the website.
 *
 * PROTOCOL_VERSION changes when the shape of desktop ↔ API traffic changes. Desktops report the
 * capabilities they implement when they register; older desktops that report none are assumed to have
 * the capabilities of their app version (see LEGACY below), so nothing is ever sent to a PC that cannot
 * handle it — in particular, encrypted provider keys only go to PCs that publish an encryption key.
 */
export const API_VERSION = '1.2.0';
export const PROTOCOL_VERSION = 2;

export type Capability =
  | 'relay.transcript'
  | 'relay.changes'
  | 'relay.filemap'
  | 'relay.diagram'
  | 'relay.tree'
  | 'relay.file'
  | 'relay.history'
  | 'relay.fileversions'
  | 'relay.providers'
  | 'relay.todos'
  | 'relay.approval'
  | 'transcript.full'
  | 'questions'
  | 'continue-on-pc'
  | 'rename'
  | 'models'
  | 'create-session'
  | 'provider-keys.encrypted'
  | 'session-stats';

/** What each feature needs, and the first BambooKit Desktop release that has it. */
export const REQUIREMENTS: Record<string, { capability: Capability; since: string; reason: string }> = {
  providers: { capability: 'relay.providers', since: '1.0.3', reason: 'Listing AI providers and models from the phone needs the newer desktop.' },
  todos: { capability: 'relay.todos', since: '1.0.3', reason: "Showing the agent's todo list needs the newer desktop." },
  approval: { capability: 'relay.approval', since: '1.0.3', reason: 'Showing the full request (command, proposed diff) needs the newer desktop.' },
  history: { capability: 'relay.history', since: '1.0.3', reason: 'Session history and before/after views need the newer desktop.' },
  fileversions: { capability: 'relay.fileversions', since: '1.0.3', reason: 'Before/after file views need the newer desktop.' },
  tree: { capability: 'relay.tree', since: '1.0.2', reason: 'Browsing project files needs the newer desktop.' },
  file: { capability: 'relay.file', since: '1.0.2', reason: 'Viewing project files needs the newer desktop.' },
  providerKeys: { capability: 'provider-keys.encrypted', since: '1.0.3', reason: 'Encrypted provider keys need the newer secure credential protocol.' },
};

/** Capabilities of desktops that registered before capability reporting existed, by app version. */
const LEGACY: Array<{ since: string; caps: Capability[] }> = [
  { since: '0.0.0', caps: ['relay.transcript', 'relay.changes', 'relay.filemap', 'relay.diagram'] },
  { since: '1.0.2', caps: ['relay.tree', 'relay.file'] },
  {
    since: '1.0.3',
    caps: [
      'relay.history', 'relay.fileversions', 'relay.providers', 'relay.todos', 'relay.approval', 'transcript.full',
      'questions', 'continue-on-pc', 'rename', 'models', 'create-session', 'provider-keys.encrypted',
    ],
  },
];

/** Compares dotted versions numerically ("1.0.10" > "1.0.9"); unknown parts count as 0. */
export function compareVersions(a: string | null | undefined, b: string): number {
  const pa = String(a ?? '0').split(/[.+-]/).map((x) => Number.parseInt(x, 10) || 0);
  const pb = b.split('.').map((x) => Number.parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

export function parseCapabilities(raw: unknown): string[] | null {
  if (typeof raw !== 'string' || !raw) return null;
  try {
    const list = JSON.parse(raw);
    return Array.isArray(list) ? list.filter((x) => typeof x === 'string') : null;
  } catch {
    return null;
  }
}

/** The capabilities a desktop has: what it reported, or what its version implies. */
export function desktopCapabilities(device: { app_version?: string | null; capabilities?: string | null; encryption_key?: string | null }): Set<string> {
  const reported = parseCapabilities(device.capabilities);
  const caps = new Set<string>(reported ?? LEGACY.filter((l) => compareVersions(device.app_version, l.since) >= 0).flatMap((l) => l.caps));
  // Encrypted keys need the PC's public key on record; only desktops that implement them publish one.
  if (device.encryption_key) caps.add('provider-keys.encrypted');
  else caps.delete('provider-keys.encrypted');
  return caps;
}

/** Throws 426 DESKTOP_UPDATE_REQUIRED (with details for the ⓘ view) when a PC lacks a feature. */
export function requireCapability(
  device: { name: string; app_version?: string | null; capabilities?: string | null; encryption_key?: string | null; protocol?: number | null },
  feature: keyof typeof REQUIREMENTS,
) {
  const req = REQUIREMENTS[feature];
  if (desktopCapabilities(device).has(req.capability)) return;
  throw new HttpError(426, 'DESKTOP_UPDATE_REQUIRED', `Update BambooKit Desktop on ${device.name}. ${req.reason}`, {
    device: device.name,
    currentVersion: device.app_version ?? null,
    requiredVersion: req.since,
    capability: req.capability,
    reason: req.reason,
    desktopProtocol: device.protocol ?? 1,
    apiProtocol: PROTOCOL_VERSION,
  });
}
