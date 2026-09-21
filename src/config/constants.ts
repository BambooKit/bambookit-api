export const CONSTANTS = {
  APP_NAME: 'BambooKit Control Plane API',
  VERSION: '0.1.0',
  DEFAULT_PAGE_SIZE: 50,
  MAX_PAGE_SIZE: 100,
  JWT_EXPIRES_IN: '7d',
  APPROVAL_EXPIRATION_HOURS: 24,
  MAX_ACTIVE_WORKERS_PER_WORKSPACE: 10,
} as const;

export const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const APPROVAL_SCOPES = ['ONCE', 'TASK', 'PROJECT', 'SESSION'] as const;
export type ApprovalScope = (typeof APPROVAL_SCOPES)[number];

export const APPROVAL_STATUSES = ['PENDING', 'APPROVED', 'REJECTED', 'EXPIRED'] as const;
export type ApprovalStatus = (typeof APPROVAL_STATUSES)[number];

export const PERMISSION_CATEGORIES = [
  'FILESYSTEM',
  'TERMINAL',
  'NETWORK',
  'GIT',
  'SECRETS',
  'CLOUD',
  'DATABASE',
  'DEPLOYMENT',
  'PRODUCTION',
] as const;
export type PermissionCategory = (typeof PERMISSION_CATEGORIES)[number];

export const PERMISSION_STATES = ['ALLOWED', 'APPROVAL_REQUIRED', 'BLOCKED'] as const;
export type PermissionState = (typeof PERMISSION_STATES)[number];

export const TASK_STATUSES = [
  'QUEUED',
  'STARTING',
  'RUNNING',
  'WAITING_FOR_APPROVAL',
  'TESTING',
  'COMPLETED',
  'FAILED',
  'CANCELLED',
] as const;
export type TaskStatus = (typeof TASK_STATUSES)[number];

export const AGENT_STATUSES = [
  'IDLE',
  'QUEUED',
  'STARTING',
  'RUNNING',
  'WAITING_FOR_APPROVAL',
  'TESTING',
  'COMPLETED',
  'FAILED',
  'CANCELLED',
] as const;
export type AgentStatus = (typeof AGENT_STATUSES)[number];

export const WORKSPACE_ROLES = ['OWNER', 'ADMIN', 'DEVELOPER', 'VIEWER'] as const;
export type WorkspaceRole = (typeof WORKSPACE_ROLES)[number];

export const PROVIDER_IDS = ['OPENAI', 'ANTHROPIC', 'GOOGLE', 'OPENROUTER', 'OLLAMA', 'CUSTOM'] as const;
export type ProviderId = (typeof PROVIDER_IDS)[number];

export const DEVICE_TYPES = ['WEB', 'WINDOWS_DESKTOP', 'ANDROID', 'CLI'] as const;
export type DeviceType = (typeof DEVICE_TYPES)[number];
