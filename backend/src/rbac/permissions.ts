/**
 * RBAC (docs/ARCHITECTURE.md §4.3). The client's claimed role is never
 * trusted — every check here is re-derived from the org_members row on
 * the server for the request being handled.
 */
import type { Role } from '../db/schema.js';

export const PERMISSIONS = [
  'org:manage_members',
  'org:view_audit_log',
  'org:manage_settings',
  'capability:create',
  'capability:revoke_any',
  'capability:revoke_own',
  'device:revoke_any',
  'device:revoke_own',
  'risk_dashboard:view',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  owner: [...PERMISSIONS],
  admin: [
    'org:manage_members', 'org:view_audit_log', 'org:manage_settings',
    'capability:create', 'capability:revoke_any', 'capability:revoke_own',
    'device:revoke_any', 'device:revoke_own', 'risk_dashboard:view',
  ],
  member: ['capability:create', 'capability:revoke_own', 'device:revoke_own'],
  // Read-only by design — a security/compliance role that can review without touching content.
  auditor: ['org:view_audit_log', 'risk_dashboard:view'],
};

export function roleHasPermission(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
}
