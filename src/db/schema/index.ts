import {
  pgTable,
  text,
  timestamp,
  varchar,
  integer,
  boolean,
  jsonb,
  primaryKey,
} from 'drizzle-orm/pg-core';

// 1. Users Table
export const users = pgTable('users', {
  id: varchar('id', { length: 64 }).primaryKey(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: text('password_hash'),
  name: varchar('name', { length: 255 }).notNull(),
  avatarUrl: text('avatar_url'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// 2. Workspaces Table
export const workspaces = pgTable('workspaces', {
  id: varchar('id', { length: 64 }).primaryKey(),
  name: varchar('name', { length: 255 }).notNull(),
  slug: varchar('slug', { length: 255 }).notNull().unique(),
  ownerId: varchar('owner_id', { length: 64 })
    .references(() => users.id, { onDelete: 'cascade' })
    .notNull(),
  tier: varchar('tier', { length: 32 }).default('FREE').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// 3. Workspace Members Table
export const workspaceMembers = pgTable(
  'workspace_members',
  {
    workspaceId: varchar('workspace_id', { length: 64 })
      .references(() => workspaces.id, { onDelete: 'cascade' })
      .notNull(),
    userId: varchar('userId', { length: 64 })
      .references(() => users.id, { onDelete: 'cascade' })
      .notNull(),
    role: varchar('role', { length: 32 }).default('DEVELOPER').notNull(), // OWNER, ADMIN, DEVELOPER, VIEWER
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.workspaceId, t.userId] }),
  })
);

// 4. Repositories Table
export const repositories = pgTable('repositories', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  provider: varchar('provider', { length: 32 }).default('GITHUB').notNull(),
  url: text('url').notNull(),
  owner: varchar('owner', { length: 255 }).notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  defaultBranch: varchar('default_branch', { length: 128 }).default('main').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// 5. Projects Table
export const projects = pgTable('projects', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  repositoryId: varchar('repository_id', { length: 64 }).references(() => repositories.id, {
    onDelete: 'set null',
  }),
  name: varchar('name', { length: 255 }).notNull(),
  slug: varchar('slug', { length: 255 }).notNull(),
  description: text('description'),
  executionMode: varchar('execution_mode', { length: 32 }).default('CLOUD').notNull(), // CLOUD, LOCAL, HYBRID
  defaultBranch: varchar('default_branch', { length: 128 }).default('main').notNull(),
  status: varchar('status', { length: 32 }).default('ACTIVE').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// 6. Agents Table
export const agents = pgTable('agents', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  projectId: varchar('project_id', { length: 64 })
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  agentType: varchar('agent_type', { length: 32 }).default('CODING').notNull(),
  provider: varchar('provider', { length: 32 }).default('ANTHROPIC').notNull(),
  model: varchar('model', { length: 128 }).notNull(),
  status: varchar('status', { length: 32 }).default('IDLE').notNull(),
  executionMode: varchar('execution_mode', { length: 32 }).default('CLOUD').notNull(),
  permissionPolicyId: varchar('permission_policy_id', { length: 64 }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// 7. Agent Tasks Table
export const agentTasks = pgTable('agent_tasks', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  projectId: varchar('project_id', { length: 64 })
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  agentId: varchar('agent_id', { length: 64 })
    .references(() => agents.id, { onDelete: 'cascade' })
    .notNull(),
  title: varchar('title', { length: 255 }).notNull(),
  prompt: text('prompt').notNull(),
  status: varchar('status', { length: 32 }).default('QUEUED').notNull(),
  executionMode: varchar('execution_mode', { length: 32 }).default('CLOUD').notNull(),
  branch: varchar('branch', { length: 128 }),
  commitSha: varchar('commit_sha', { length: 64 }),
  startedAt: timestamp('started_at'),
  completedAt: timestamp('completed_at'),
  error: text('error'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// 8. Agent Events Table (Immutable Event Sourcing / Replay Ledger)
export const agentEvents = pgTable('agent_events', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  projectId: varchar('project_id', { length: 64 })
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  agentId: varchar('agent_id', { length: 64 })
    .references(() => agents.id, { onDelete: 'cascade' })
    .notNull(),
  taskId: varchar('task_id', { length: 64 })
    .references(() => agentTasks.id, { onDelete: 'cascade' })
    .notNull(),
  type: varchar('type', { length: 64 }).notNull(),
  summary: text('summary').notNull(),
  payload: jsonb('payload'),
  severity: varchar('severity', { length: 32 }).default('INFO').notNull(),
  actor: varchar('actor', { length: 64 }).default('AGENT').notNull(),
  timestamp: timestamp('timestamp').defaultNow().notNull(),
});

// 9. Dangerous Action Approvals Table
export const approvalRequests = pgTable('approval_requests', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  projectId: varchar('project_id', { length: 64 })
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  agentId: varchar('agent_id', { length: 64 })
    .references(() => agents.id, { onDelete: 'cascade' })
    .notNull(),
  taskId: varchar('task_id', { length: 64 })
    .references(() => agentTasks.id, { onDelete: 'cascade' })
    .notNull(),
  action: varchar('action', { length: 255 }).notNull(),
  riskLevel: varchar('risk_level', { length: 32 }).default('HIGH').notNull(), // LOW, MEDIUM, HIGH, CRITICAL
  scope: varchar('scope', { length: 32 }).default('ONCE').notNull(), // ONCE, TASK, PROJECT, SESSION
  reason: text('reason').notNull(),
  resources: jsonb('resources'),
  status: varchar('status', { length: 32 }).default('PENDING').notNull(), // PENDING, APPROVED, REJECTED, EXPIRED
  details: jsonb('details'),
  requestedAt: timestamp('requested_at').defaultNow().notNull(),
  expiresAt: timestamp('expires_at'),
  resolvedAt: timestamp('resolved_at'),
  resolvedById: varchar('resolved_by_id', { length: 64 }).references(() => users.id, {
    onDelete: 'set null',
  }),
});

// 10. Permission Policies Table
export const permissionPolicies = pgTable('permission_policies', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  category: varchar('category', { length: 64 }).notNull(), // FILESYSTEM, TERMINAL, GIT, etc.
  state: varchar('state', { length: 32 }).default('ALLOWED').notNull(), // ALLOWED, APPROVAL_REQUIRED, BLOCKED
  rules: jsonb('rules'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// 11. Provider Configurations Table (BYOK)
export const providerConfigs = pgTable('provider_configs', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  provider: varchar('provider', { length: 32 }).notNull(), // OPENAI, ANTHROPIC, GOOGLE, etc.
  name: varchar('name', { length: 255 }).notNull(),
  baseUrl: text('base_url'),
  defaultModel: varchar('default_model', { length: 128 }).notNull(),
  encryptedApiKey: text('encrypted_api_key'),
  keyIv: varchar('key_iv', { length: 64 }),
  keyTag: varchar('key_tag', { length: 64 }),
  enabled: boolean('enabled').default(true).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// 12. Remote Devices Table (Desktop / Mobile Connectors)
export const devices = pgTable('devices', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  userId: varchar('user_id', { length: 64 })
    .references(() => users.id, { onDelete: 'cascade' })
    .notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  type: varchar('type', { length: 32 }).default('WEB').notNull(), // WEB, WINDOWS_DESKTOP, ANDROID, CLI
  status: varchar('status', { length: 32 }).default('ONLINE').notNull(),
  version: varchar('version', { length: 64 }).notNull(),
  publicKey: text('public_key'),
  lastSeenAt: timestamp('last_seen_at').defaultNow().notNull(),
  ipAddressMasked: varchar('ip_address_masked', { length: 64 }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// 13. Deployments Table
export const deployments = pgTable('deployments', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  projectId: varchar('project_id', { length: 64 })
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  environment: varchar('environment', { length: 32 }).default('PRODUCTION').notNull(), // DEVELOPMENT, STAGING, PRODUCTION
  commitSha: varchar('commit_sha', { length: 64 }).notNull(),
  commitMessage: text('commit_message'),
  status: varchar('status', { length: 32 }).default('QUEUED').notNull(), // QUEUED, BUILDING, DEPLOYING, READY, FAILED
  url: text('url'),
  durationSeconds: integer('duration_seconds').default(0),
  deployedByAgentId: varchar('deployed_by_agent_id', { length: 64 }).references(() => agents.id, {
    onDelete: 'set null',
  }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// 14. Usage Records Table
export const usageRecords = pgTable('usage_records', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  projectId: varchar('project_id', { length: 64 }).references(() => projects.id, {
    onDelete: 'set null',
  }),
  agentId: varchar('agent_id', { length: 64 }).references(() => agents.id, {
    onDelete: 'set null',
  }),
  provider: varchar('provider', { length: 32 }).notNull(),
  model: varchar('model', { length: 128 }).notNull(),
  inputTokens: integer('input_tokens').default(0).notNull(),
  outputTokens: integer('output_tokens').default(0).notNull(),
  estimatedCostUsd: text('estimated_cost_usd').default('0.00').notNull(),
  workerSeconds: integer('worker_seconds').default(0).notNull(),
  storageBytes: integer('storage_bytes').default(0).notNull(),
  timestamp: timestamp('timestamp').defaultNow().notNull(),
});

// 15. Notifications Table
export const notifications = pgTable('notifications', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  userId: varchar('user_id', { length: 64 })
    .references(() => users.id, { onDelete: 'cascade' })
    .notNull(),
  type: varchar('type', { length: 64 }).notNull(), // APPROVAL_REQUIRED, AGENT_COMPLETED, DEPLOYMENT_COMPLETED, etc.
  title: varchar('title', { length: 255 }).notNull(),
  body: text('body').notNull(),
  read: boolean('read').default(false).notNull(),
  link: text('link'),
  metadata: jsonb('metadata'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

// 16. Audit Events Table (Immutable Compliance Log)
export const auditEvents = pgTable('audit_events', {
  id: varchar('id', { length: 64 }).primaryKey(),
  workspaceId: varchar('workspace_id', { length: 64 })
    .references(() => workspaces.id, { onDelete: 'cascade' })
    .notNull(),
  actorType: varchar('actor_type', { length: 32 }).notNull(), // USER, AGENT, SYSTEM, DEVICE
  actorId: varchar('actor_id', { length: 64 }).notNull(),
  actorName: varchar('actor_name', { length: 255 }).notNull(),
  action: varchar('action', { length: 255 }).notNull(),
  resourceType: varchar('resource_type', { length: 64 }).notNull(),
  resourceId: varchar('resource_id', { length: 64 }).notNull(),
  metadata: jsonb('metadata'),
  ipAddress: varchar('ip_address', { length: 64 }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});
