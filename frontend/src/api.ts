// Klient REST API v1. Sesję trzyma ciasteczko HttpOnly `asi_session`, które przeglądarka
// wysyła sama (ten sam origin), więc JavaScript nie widzi ani nie przechowuje tokenu.

import type { Change, Dashboard, DefectDojoResult, FileFormat, ImportSummary, Page, ResultRow, Role, Run, Schedule, Session, Severity, SignatureList, Target, TargetPatch, User, VulnMode, VulnPage } from "./types";

const API_PREFIX = "/api/v1";

// 401 wylogowuje tylko zalogowanego użytkownika; 401 z błędnego hasła lub pierwszego /me nie.
let loggedIn = false;
let onUnauthorized: () => void = () => {};

export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

interface RequestOptions {
  json?: unknown;
  text?: string;
}

async function send(method: Method, path: string, options: RequestOptions = {}): Promise<Response> {
  const headers: Record<string, string> = {};
  let body: string | undefined;
  if (options.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.json);
  } else if (options.text !== undefined) {
    headers["Content-Type"] = "text/plain; charset=utf-8";
    body = options.text;
  }

  const response = await fetch(API_PREFIX + path, { method, headers, body });

  if (response.status === 401 && loggedIn) {
    loggedIn = false;
    onUnauthorized();
  }
  if (!response.ok) {
    throw new ApiError(await readErrorMessage(response), response.status);
  }
  return response;
}

async function readErrorMessage(response: Response): Promise<string> {
  try {
    const data = await response.json();
    return data.error ?? response.statusText;
  } catch {
    return response.statusText;
  }
}

async function request<T>(method: Method, path: string, options?: RequestOptions): Promise<T> {
  const response = await send(method, path, options);
  // puste ciało (204, 202 przy starcie sprawdzania CVE itp.) = brak danych, bez parsowania JSON
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

async function startSession(pending: Promise<Session>): Promise<Session> {
  const session = await pending;
  loggedIn = true;
  return session;
}

export const api = {
  login: (username: string, password: string) =>
    startSession(request<Session>("POST", "/auth/login", { json: { username, password } })),

  /** Bieżąca sesja z ciasteczka; 401, gdy nikt nie jest zalogowany. */
  me: () => startSession(request<Session>("GET", "/me")),

  /** Rzuca wyjątek przy błędzie — wylogowanie potwierdza dopiero odpowiedź serwera. */
  logout: async () => {
    await request<void>("POST", "/auth/logout");
    loggedIn = false;
  },

  authConfig: () => request<{ session_ttl_hours: number }>("GET", "/auth/config"),

  dashboard: () => request<Dashboard>("GET", "/dashboard"),

  targets: {
    list: () => request<Target[]>("GET", "/targets"),
    addText: (text: string) => request<ImportSummary>("POST", "/targets", { json: { text } }),
    importFile: (format: FileFormat, content: string, dryRun: boolean) =>
      request<ImportSummary>("POST", `/targets/import?format=${format}&dry_run=${dryRun}`, { text: content }),
    update: (id: string, patch: TargetPatch) => request<void>("PATCH", `/targets/${id}`, { json: patch }),
    remove: (id: string) => request<void>("DELETE", `/targets/${id}`),
  },

  runs: {
    list: () => request<Run[]>("GET", "/runs"),
    start: (targetIds: string[], vulnCheck: VulnMode) =>
      request<{ run_id: string }>("POST", "/runs", { json: { target_ids: targetIds, vuln_check: vulnCheck } }),
    cancel: (id: string) => request<void>("POST", `/runs/${id}/cancel`),
    changes: (id: string, offset = 0) => request<Page<Change>>("GET", `/runs/${id}/changes?limit=200&offset=${offset}`),
    observations: (id: string, offset = 0) =>
      request<Page<ResultRow>>("GET", `/runs/${id}/observations?limit=100&offset=${offset}`),
    exportFile: async (id: string, format: "csv" | "json") => {
      const response = await send("GET", `/runs/${id}/export?format=${format}`);
      return response.blob();
    },
    /** Raport PDF z backendu; nazwa pliku z nagłówka Content-Disposition. */
    reportPdf: async (id: string) => {
      const response = await send("GET", `/runs/${id}/report.pdf`);
      const name = /filename="([^"]+)"/.exec(response.headers.get("Content-Disposition") ?? "")?.[1] ?? `asi-raport-${id}.pdf`;
      return { blob: await response.blob(), name };
    },
    vulnerabilities: (id: string, offset = 0, severity?: Severity) =>
      request<VulnPage>("GET", `/runs/${id}/vulnerabilities?limit=100&offset=${offset}${severity ? `&severity=${severity}` : ""}`),
    startVulnCheck: (id: string) => request<void>("POST", `/runs/${id}/vuln-check`),
    skipVulnCheck: (id: string) => request<void>("POST", `/runs/${id}/vuln-check/skip`),
    /** Info z wynikami CVE do DefectDojo (engagement per IP). */
    sendToDefectDojo: (id: string) => request<DefectDojoResult>("POST", `/runs/${id}/defectdojo`),
    importResults: (format: FileFormat, content: string) =>
      request<{ run_id: string; observations: number; changes: number }>("POST", `/results/import?format=${format}`, {
        text: content,
      }),
  },

  schedule: {
    get: () => request<Schedule>("GET", "/schedule"),
    save: (schedule: Schedule) => request<void>("PUT", "/schedule", { json: schedule }),
  },

  overrides: {
    set: (key: string, field: string, value: string, reason?: string) =>
      request<{ id: string }>("PUT", "/overrides", { json: { key, field, value, reason } }),
    remove: (key: string, field: string) =>
      request<void>("DELETE", `/overrides?key=${encodeURIComponent(key)}&field=${encodeURIComponent(field)}`),
  },

  signatures: {
    list: () => request<SignatureList>("GET", "/signatures"),
    add: (yaml: string) => request<{ created: string[] }>("POST", "/signatures", { json: { yaml } }),
    update: (slug: string, yaml: string) => request<{ updated: string }>("PUT", `/signatures/${slug}`, { json: { yaml } }),
    disable: (slug: string) => request<void>("DELETE", `/signatures/${slug}`),
  },

  users: {
    list: () => request<User[]>("GET", "/admin/users"),
    create: (username: string, password: string, role: Role) =>
      request<{ id: string }>("POST", "/admin/users", { json: { username, password, role } }),
    update: (id: string, patch: { role?: Role; password?: string; disabled?: boolean }) =>
      request<void>("PATCH", `/admin/users/${id}`, { json: patch }),
    remove: (id: string) => request<void>("DELETE", `/admin/users/${id}`),
  },
};
