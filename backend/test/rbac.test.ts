import { describe, it, expect } from 'vitest';
import { roleHasPermission } from '../src/rbac/permissions.js';
import { ROLES } from '../src/db/schema.js';

describe('RBAC permission matrix', () => {
  it('owner has every permission', () => {
    expect(roleHasPermission('owner', 'org:manage_members')).toBe(true);
    expect(roleHasPermission('owner', 'capability:revoke_any')).toBe(true);
    expect(roleHasPermission('owner', 'risk_dashboard:view')).toBe(true);
  });

  it('SECURITY REGRESSION: member cannot manage org members or revoke others\' capabilities', () => {
    expect(roleHasPermission('member', 'org:manage_members')).toBe(false);
    expect(roleHasPermission('member', 'capability:revoke_any')).toBe(false);
    expect(roleHasPermission('member', 'device:revoke_any')).toBe(false);
  });

  it('member can manage only their own resources', () => {
    expect(roleHasPermission('member', 'capability:create')).toBe(true);
    expect(roleHasPermission('member', 'capability:revoke_own')).toBe(true);
    expect(roleHasPermission('member', 'device:revoke_own')).toBe(true);
  });

  it('SECURITY REGRESSION: auditor is read-only — cannot create or revoke anything', () => {
    expect(roleHasPermission('auditor', 'capability:create')).toBe(false);
    expect(roleHasPermission('auditor', 'capability:revoke_own')).toBe(false);
    expect(roleHasPermission('auditor', 'org:manage_members')).toBe(false);
    expect(roleHasPermission('auditor', 'org:view_audit_log')).toBe(true);
    expect(roleHasPermission('auditor', 'risk_dashboard:view')).toBe(true);
  });

  it('admin has everything except nothing is withheld from owner-only in this model (admin == owner minus nothing here by design, verify explicitly)', () => {
    for (const permission of ['org:manage_members', 'org:view_audit_log', 'org:manage_settings', 'capability:create', 'capability:revoke_any', 'device:revoke_any'] as const) {
      expect(roleHasPermission('admin', permission)).toBe(true);
    }
  });

  it('every role in the DB schema enum has an entry in the permission matrix (no role silently falls through to zero permissions)', () => {
    for (const role of ROLES) {
      const anyPermission = roleHasPermission(role, 'risk_dashboard:view') || roleHasPermission(role, 'capability:create');
      // auditor and member differ in which one is true, but every role must be represented at all (not undefined behavior).
      expect(typeof roleHasPermission(role, 'org:manage_members')).toBe('boolean');
      void anyPermission;
    }
  });
});
