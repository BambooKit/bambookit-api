import { env } from '../config/env.js';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

function shouldLog(level: LogLevel): boolean {
  return LEVELS[level] >= LEVELS[env.LOG_LEVEL as LogLevel];
}

function formatLog(level: LogLevel, message: string, meta?: Record<string, any>): string {
  const payload = {
    timestamp: new Date().toISOString(),
    level: level.toUpperCase(),
    message,
    ...meta,
  };
  return JSON.stringify(payload);
}

export const logger = {
  debug(message: string, meta?: Record<string, any>) {
    if (shouldLog('debug')) console.debug(formatLog('debug', message, meta));
  },
  info(message: string, meta?: Record<string, any>) {
    if (shouldLog('info')) console.info(formatLog('info', message, meta));
  },
  warn(message: string, meta?: Record<string, any>) {
    if (shouldLog('warn')) console.warn(formatLog('warn', message, meta));
  },
  error(message: string, meta?: Record<string, any>) {
    if (shouldLog('error')) console.error(formatLog('error', message, meta));
  },
};
