// Uprawnienia ról po stronie interfejsu. Służą tylko do ukrywania przycisków;
// właściwa kontrola dostępu odbywa się w backendzie (src/auth.rs).

import type { Role } from "./types";

export type Permission = "create" | "modify" | "delete" | "scan" | "signatures" | "users";

const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  admin: ["create", "modify", "delete", "scan", "signatures", "users"],
  editor: ["create", "modify", "delete", "scan", "signatures"],
  analyst: ["modify"],
  viewer: [],
};

export function can(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}

export const ROLES: Role[] = ["viewer", "analyst", "editor", "admin"];

/** Nazwy ról zgodne z treścią zadania (pkt 13). */
export const ROLE_LABELS: Record<Role, string> = {
  admin: "Administracja",
  editor: "Dodawanie, usuwanie, modyfikacja",
  analyst: "Modyfikacja i odczyt",
  viewer: "Odczyt",
};
