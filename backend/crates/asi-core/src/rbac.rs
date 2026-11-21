//! Uprawnienia i wbudowane role zgodnie z tabelą §14.1 dokumentu projektowego.
//! Ta macierz jest jedynym źródłem prawdy: seed bazy i testy 200/403 korzystają z niej.

pub const READ: &str = "read";
pub const EXPORT: &str = "export";
pub const DATA_UPDATE: &str = "data.update";
pub const SCANS_CONFIGURE: &str = "scans.configure";
pub const SCANS_RUN: &str = "scans.run";
pub const TARGETS_CREATE: &str = "targets.create";
pub const TARGETS_UPDATE: &str = "targets.update";
pub const TARGETS_DELETE: &str = "targets.delete";
pub const SIGNATURES_CREATE: &str = "signatures.create";
pub const SIGNATURES_UPDATE: &str = "signatures.update";
pub const SIGNATURES_DELETE: &str = "signatures.delete";
pub const INTEGRATIONS_EXPORT: &str = "integrations.export";
pub const ADMIN_USERS: &str = "admin.users";
pub const ADMIN_SETTINGS: &str = "admin.settings";
pub const ADMIN_AUDIT: &str = "admin.audit";
/// Odsłonięcie wartości ciasteczek i nagłówków zapisanych w wynikach (audytowane).
pub const RESULTS_REVEAL: &str = "results.reveal";

pub const ALL_PERMISSIONS: &[&str] = &[
    READ,
    EXPORT,
    DATA_UPDATE,
    SCANS_CONFIGURE,
    SCANS_RUN,
    TARGETS_CREATE,
    TARGETS_UPDATE,
    TARGETS_DELETE,
    SIGNATURES_CREATE,
    SIGNATURES_UPDATE,
    SIGNATURES_DELETE,
    INTEGRATIONS_EXPORT,
    ADMIN_USERS,
    ADMIN_SETTINGS,
    ADMIN_AUDIT,
    RESULTS_REVEAL,
];

pub const ADMIN: &str = "admin";
pub const EDITOR: &str = "editor";
pub const ANALYST: &str = "analyst";
pub const VIEWER: &str = "viewer";

pub const BUILTIN_ROLES: &[&str] = &[ADMIN, EDITOR, ANALYST, VIEWER];

/// Uprawnienia wbudowanej roli. Analityk dostaje `targets.update` (rola „modyfikacja i odczyt”),
/// ale nie dodaje ani nie usuwa celów (design D3).
pub fn role_permissions(role: &str) -> &'static [&'static str] {
    match role {
        ADMIN => ALL_PERMISSIONS,
        EDITOR => &[
            READ,
            EXPORT,
            DATA_UPDATE,
            SCANS_CONFIGURE,
            SCANS_RUN,
            TARGETS_CREATE,
            TARGETS_UPDATE,
            TARGETS_DELETE,
            SIGNATURES_CREATE,
            SIGNATURES_UPDATE,
            SIGNATURES_DELETE,
            INTEGRATIONS_EXPORT,
        ],
        ANALYST => &[
            READ,
            EXPORT,
            DATA_UPDATE,
            SCANS_CONFIGURE,
            SCANS_RUN,
            TARGETS_UPDATE,
            SIGNATURES_UPDATE,
            INTEGRATIONS_EXPORT,
        ],
        VIEWER => &[READ, EXPORT],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(role: &str, perm: &str) -> bool {
        role_permissions(role).contains(&perm)
    }

    #[test]
    fn matrix_matches_section_14_1() {
        assert_eq!(role_permissions(VIEWER), &[READ, EXPORT]);
        for perm in [ADMIN_USERS, ADMIN_SETTINGS, ADMIN_AUDIT, RESULTS_REVEAL] {
            assert!(has(ADMIN, perm));
            for role in [EDITOR, ANALYST, VIEWER] {
                assert!(!has(role, perm), "{role} nie może mieć {perm}");
            }
        }
        for perm in [
            TARGETS_CREATE,
            TARGETS_DELETE,
            SIGNATURES_CREATE,
            SIGNATURES_DELETE,
        ] {
            assert!(has(EDITOR, perm));
            assert!(!has(ANALYST, perm));
        }
        for perm in [
            DATA_UPDATE,
            SCANS_RUN,
            SIGNATURES_UPDATE,
            INTEGRATIONS_EXPORT,
        ] {
            assert!(has(ANALYST, perm));
            assert!(!has(VIEWER, perm));
        }
    }

    #[test]
    fn every_role_permission_is_known() {
        for role in BUILTIN_ROLES {
            for perm in role_permissions(role) {
                assert!(ALL_PERMISSIONS.contains(perm));
            }
        }
    }
}
