// Uprawnienia w interfejsie pochodzą z profilu `/api/v1/me` (kody z backend/crates/asi-core/src/rbac.rs).
// Służą tylko do ukrywania przycisków; dostęp egzekwuje backend (403).

import type { Role, Session } from "./types";

export type Permission =
  | "read"
  | "export"
  | "data.update"
  | "scans.run"
  | "targets.create"
  | "targets.update"
  | "targets.delete"
  | "signatures.create"
  | "signatures.update"
  | "signatures.delete"
  | "integrations.export"
  | "admin.users"
  | "admin.audit";

export function can(session: Session, permission: Permission): boolean {
  return session.permissions.includes(permission);
}

export const ROLES: Role[] = ["viewer", "analyst", "editor", "admin"];
