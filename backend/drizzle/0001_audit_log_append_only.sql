-- Enforces append-only at the database level (docs/ARCHITECTURE.md §5.5):
-- the hash-chain design in src/audit/auditLog.ts assumes rows are never
-- edited or removed after insert. This trigger makes that a DB-level
-- guarantee, not just an application-code convention that a bug (or a
-- direct psql session) could violate.
--
-- Scope note: this blocks row-level UPDATE/DELETE, not TRUNCATE or DROP
-- TABLE by a role with DDL privileges — a genuinely privileged Postgres
-- role can always bypass application-level controls (disable the trigger,
-- truncate, restore from a doctored backup). Closing that gap needs an
-- infrastructure-level control (a dedicated write-only DB role with
-- TRUNCATE/DDL revoked, shipping the hash chain to independent
-- write-once storage), which is out of scope for this reference
-- deployment and noted here rather than silently assumed away.
CREATE OR REPLACE FUNCTION audit_log_prevent_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_prevent_mutation();

CREATE TRIGGER audit_log_no_delete
  BEFORE DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_prevent_mutation();
