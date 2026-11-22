// Typy odpowiedzi API v1. Odpowiadają strukturom z backend/ (asi-db, asi-core::export).

export type Role = "admin" | "editor" | "analyst" | "viewer";

/** Profil z `GET /api/v1/me` i logowania. */
export interface Session {
  id: string;
  username: string;
  roles: Role[];
  permissions: string[];
}

export interface Target {
  id: string;
  kind: "ip" | "cidr" | "domain";
  value: string;
  source: string;
  excluded: boolean;
  tags: string[];
  note: string | null;
  created_at: string;
  updated_at: string;
}

export interface TargetPatch {
  tags?: string[];
  note?: string;
  excluded?: boolean;
}

export interface ImportSummary {
  rows: number;
  accepted: number;
  duplicates: number;
  rejected: { row: number; value: string }[];
  dry_run: boolean;
}

export type RunStatus = "queued" | "running" | "done" | "partial" | "failed" | "cancelled";

export interface Coverage {
  planned?: number;
  scanned?: number;
  pending?: number;
  failed?: number;
  live_hosts?: number;
  services?: number;
  http_probed?: number;
}

export interface Run {
  id: string;
  kind: "scan" | "import";
  status: RunStatus;
  reason: string | null;
  coverage: Coverage;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  /** Cele w kolejce przebiegu; w trakcie skanu aktualizowane co ~1 s. */
  hosts_total: number;
  /** Cele z zakończonych podgrup (≤ hosts_total). */
  hosts_done: number;
  created_at: string;
  vuln_state: VulnState;
  vuln_reason: string | null;
  /** Po sprawdzeniu: services, identified, unidentified, vulnerabilities, confirmed, verify. */
  vuln_summary: Partial<Record<"services" | "identified" | "unidentified" | "vulnerabilities" | "confirmed", number>>;
  /** Ostatnia wysyłka do DefectDojo (automatyczna albo ręczna); null = jeszcze nie było. */
  dd_export: DefectDojoExport | null;
  /** Pozycja harmonogramu, która uruchomiła przebieg; null = start ręczny. */
  schedule_id: string | null;
  schedule_name: string | null;
}

export interface DefectDojoExport {
  at: string;
  /** inventory = same wyniki skanu, all = wyniki z opisem CVE. */
  content: "inventory" | "all";
  findings?: number;
  engagements?: number;
  failed?: string[];
  error: string | null;
}

export type VulnState = "none" | "pending_decision" | "running" | "done" | "failed" | "skipped";
export type VulnMode = "auto" | "ask" | "off";
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface Vulnerability {
  ip: string;
  port: number;
  proto: string;
  cve_id: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity: Severity;
  /** version_match = korelacja wersji (potencjalna), confirmed = potwierdzona sondą. */
  evidence: "version_match" | "confirmed";
  component: string;
  version: string;
  description: string;
  published: string | null;
}

export interface DefectDojoResult {
  findings: number;
  engagements: { ip: string; engagement_id: number; created: boolean }[];
  failed: { ip: string; error: string }[];
}

export interface VulnPage {
  total: number;
  items: Vulnerability[];
  summary: {
    state: VulnState;
    reason: string | null;
    by_severity: Record<Severity, number>;
    confirmed: number;
    unidentified: number | null;
    services: number | null;
  };
}

export type ChangeKind = "new" | "gone" | "changed" | "host_inactive" | "host_returned";

export interface Change {
  id: number;
  kind: ChangeKind;
  entity_key: string;
  ip: string;
  field: string | null;
  before: string | null;
  after: string | null;
}

export interface Page<T> {
  total: number;
  items: T[];
}

export interface Detection {
  signature_id: string;
  name: string;
  category: string;
  version: string | null;
  confidence: number;
  evidence: string[];
}

export interface HttpView {
  status: number;
  title: string | null;
  final_url: string;
  redirects: string[];
  blocked_redirects: string[];
  headers: Record<string, string>;
  cookies: { name: string; attributes: string[] }[];
  tls: TlsCert | null;
}

export interface TlsCert {
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  sha256: string;
}

/** Wynik po korektach analityka; surowy pomiar w `raw_*`. */
export interface ResultRow {
  id: string;
  key: string;
  ip: string;
  hostname: string | null;
  port: number;
  proto: string;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
  http: HttpView | null;
  technologies: Detection[];
  status: string | null;
  severity: string | null;
  owner: string | null;
  note: string | null;
  raw_service: string | null;
  raw_product: string | null;
  raw_version: string | null;
}

export interface Dashboard {
  targets: number;
  assets: Partial<Record<"active" | "unstable" | "inactive", number>>;
  latest_run: Run | null;
  scan_running: boolean;
  /** Zakończone skany (`done`/`partial`) od początku, bez importów. */
  scans_total: number;
  services: number;
  changes_total: number;
  technologies: { name: string; category: string; services: number }[];
  notable: { ip: string; port: number; name: string; category: string; title: string | null; confidence: number }[];
  recent_changes: Change[];
}

export interface SignatureList {
  /** `yaml` w formacie POST /signatures: edycja wbudowanej tworzy jej nadpisanie. */
  builtin: { id: string; name: string; category: string; yaml: string }[];
  custom: { slug: string; version: number; yaml: string; enabled: boolean; created_at: string }[];
}

export interface User {
  id: string;
  username: string;
  disabled: boolean;
  roles: Role[];
  created_at: string;
}

export interface ScheduleWindow {
  /** HH:MM, czas serwera */
  start: string;
  end: string;
  /** mon..sun; pusta lista = codziennie */
  days: string[];
}

/** Pozycja harmonogramu do zapisu (`POST /schedules`, `PUT /schedules/{id}`). */
export interface ScheduleInput {
  name: string;
  enabled: boolean;
  every_hours: number;
  windows: ScheduleWindow[];
  target_ids: string[];
  vuln_check: VulnMode;
}

/** Pozycja harmonogramu z `GET /schedules`: ostatni przebieg tej pozycji i liczba usuniętych celów. */
export interface ScheduleEntry extends ScheduleInput {
  id: string;
  last_run_at: string | null;
  last_status: RunStatus | null;
  missing_targets: number;
}

export type FileFormat = "csv" | "json" | "text";
