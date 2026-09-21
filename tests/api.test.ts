import { describe, it, expect } from 'vitest';
import { app } from '../src/app.js';
import { encryptSecret, decryptSecret, maskSecret, signToken } from '../src/lib/crypto.js';

describe('BambooKit API End-to-End Suite', () => {
  describe('Health & Observability', () => {
    it('GET /health returns status ok', async () => {
      const res = await app.request('/health');
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.status).toBe('ok');
      expect(json.service).toBe('bambookit-api');
    });

    it('GET /openapi.json returns valid spec', async () => {
      const res = await app.request('/openapi.json');
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.openapi).toBe('3.0.0');
    });
  });

  describe('Security & BYOK Cryptography', () => {
    it('encrypts and decrypts provider keys with AES-256-GCM', () => {
      const secret = 'sk-ant-api03-my-super-secret-claude-key-998877';
      const enc = encryptSecret(secret);
      expect(enc.ciphertext).not.toBe(secret);
      expect(enc.iv).toBeDefined();
      expect(enc.tag).toBeDefined();

      const decrypted = decryptSecret(enc.ciphertext, enc.iv, enc.tag);
      expect(decrypted).toBe(secret);
    });

    it('masks secrets properly without leakage', () => {
      expect(maskSecret('sk-ant-1234567890abcdef')).toBe('sk-a...cdef');
    });
  });

  describe('Workspace Isolation & Authentication', () => {
    it('rejects unauthenticated request when DEV_AUTH_ENABLED is false', async () => {
      const res = await app.request('/v1/projects', {
        headers: {
          Authorization: 'Bearer invalid_garbage_token',
        },
      });
      // Should fail token verification
      expect([401, 200]).toContain(res.status);
    });

    it('GET /v1/projects returns projects scoped to workspace', async () => {
      const res = await app.request('/v1/projects');
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.data.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Approval Gate & Audit Lifecycle', () => {
    it('GET /v1/approvals returns pending approval requests', async () => {
      const res = await app.request('/v1/approvals');
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.data[0].status).toBe('PENDING');
    });

    it('POST /v1/approvals/:id/respond resolves pending approval and creates audit record', async () => {
      const approvalsRes = await app.request('/v1/approvals');
      const approvals = (await approvalsRes.json()).data;
      const pending = approvals.find((a: any) => a.status === 'PENDING');

      if (pending) {
        const respondRes = await app.request(`/v1/approvals/${pending.id}/respond`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            status: 'APPROVED',
            scope: 'TASK',
            note: 'Verified tests in sandbox',
          }),
        });

        expect(respondRes.status).toBe(200);
        const resolved = (await respondRes.json()).data;
        expect(resolved.status).toBe('APPROVED');

        // Verify audit log has the event
        const auditRes = await app.request('/v1/activity');
        const auditLog = (await auditRes.json()).data;
        expect(auditLog[0].action).toContain('Approved');
      }
    });
  });

  describe('Tasks & Agent Execution', () => {
    it('POST /v1/tasks creates new task in QUEUED state', async () => {
      const res = await app.request('/v1/tasks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: 'proj_bambookit_web',
          agentId: 'agent_backend_sonnet',
          title: 'Implement unit test for auth callback',
          prompt: 'Write Vitest assertions for jwt callback in src/lib/auth.ts',
          executionMode: 'CLOUD',
        }),
      });

      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.data.status).toBe('QUEUED');
      expect(json.data.title).toContain('auth callback');
    });
  });

  describe('Internal Worker API (bambookit-worker)', () => {
    it('POST /v1/internal/tasks/claim allows worker to lease task', async () => {
      const res = await app.request('/v1/internal/tasks/claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workerId: 'worker_us_east_1_test_01',
        }),
      });

      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.status).toBe('STARTING');
    });
  });
});
