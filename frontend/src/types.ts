// Typy odpowiedzi API. Odpowiadają strukturom z backendu (src/model.rs, src/db, src/diff.rs).

export type Role = "admin" | "editor" | "analyst" | "viewer";

export interface Session {
  token: string;
  username: string;
  role: Role;
}

export interface Target {
  id: string;
  value: string;
  kind: "ip" | "cidr" | "domain";
  tags: string[];
  note: string | null;
  enabled: boolean;
  source: string;
  created_at: string;
  updated_at: string;
}

export interface TargetPatch {
  tags?: string[];
  note?: string;
  enabled?: boolean;
}

export interface ImportSummary {
  parsed: number;
  inserted: number;
  invalid: string[];
}

export type RunStatus = "running" | "completed" | "partial" | "aborted" | "failed";

export interface Run {
  id: string;
  source: string;
  status: RunStatus;
  started_at: string;
  finished_at: string | null;
  duration_secs: number | null;
  stats_json: string | null;
}

export interface RunStats {
  live_hosts?: number;
  services?: number;
  changes?: number;
  pending?: number;
  failed?: number;
}

export type ChangeKind = "new" | "gone" | "changed" | "host_inactive" | "host_returned";

export interface Change {
  kind: ChangeKind;
  key: string;
  ip: string;
  field: string | null;
  before: string | null;
  after: string | null;
}

export interface Detection {
  signature_id: string;
  name: string;
  category: string;
  version: string | null;
  confidence: number;
  evidence: string[];
}

export interface HttpInfo {
  url: string;
  final_url: string;
  status: number;
  title: string | null;
  headers: Record<string, string>;
  cookies: string[];
  redirects: string[];
}

export interface Observation {
  ip: string;
  hostname: string | null;
  port: number;
  proto: string;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
  http: HttpInfo | null;
  detections: Detection[];
}

export interface NotableFinding {
  key: string;
  name: string;
  category: string;
  confidence: number;
  title: string | null;
}

export interface Dashboard {
  counts: {
    targets: number;
    hosts: Partial<Record<"active" | "unstable" | "inactive", number>>;
  };
  latest_run: Run | null;
  services: number;
  technologies: [string, number][];
  interesting: NotableFinding[];
  changes: Change[];
  scan_running: boolean;
}

export interface SignatureRule {
  type: string;
}

export interface Signature {
  id: string;
  name: string;
  category: string;
  confidence: number;
  rules: SignatureRule[];
}

export interface CustomSignature {
  id: string;
  name: string;
  yaml: string;
  enabled: number;
  created_by: string;
  created_at: string;
}

export interface SignatureList {
  active: Signature[];
  custom: CustomSignature[];
}

export interface User {
  id: string;
  username: string;
  role: Role;
  created_at: string;
}

export type FileFormat = "csv" | "json" | "txt";
