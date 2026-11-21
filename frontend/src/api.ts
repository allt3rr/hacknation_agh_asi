// Klient REST API. Token sesji jest ustawiany po zalogowaniu (setAuthToken).

import type {
  Change,
  Dashboard,
  FileFormat,
  ImportSummary,
  Observation,
  Role,
  Run,
  Session,
  SignatureList,
  Target,
  TargetPatch,
  User,
} from "./types";

const API_PREFIX = "/api";

let authToken: string | null = null;
let onUnauthorized: () => void = () => {};

export function setAuthToken(token: string | null) {
  authToken = token;
}

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

type Method = "GET" | "POST" | "PUT" | "DELETE";

interface RequestOptions {
  json?: unknown;
  text?: string;
}

async function send(method: Method, path: string, options: RequestOptions = {}): Promise<Response> {
  const headers: Record<string, string> = {};
  if (authToken) {
    headers.Authorization = `Bearer ${authToken}`;
  }

  let body: string | undefined;
  if (options.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.json);
  } else if (options.text !== undefined) {
    headers["Content-Type"] = "text/plain; charset=utf-8";
    body = options.text;
  }

  const response = await fetch(API_PREFIX + path, { method, headers, body });

  if (response.status === 401 && authToken) {
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
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<Session>("POST", "/login", { json: { username, password } }),

  logout: () => request<void>("POST", "/logout"),

  dashboard: () => request<Dashboard>("GET", "/dashboard"),

  targets: {
    list: () => request<Target[]>("GET", "/targets"),
    addText: (text: string) => request<ImportSummary>("POST", "/targets", { json: { text } }),
    importFile: (format: FileFormat, content: string) =>
      request<ImportSummary>("POST", `/targets/import?format=${format}`, { text: content }),
    update: (id: string, patch: TargetPatch) => request<void>("PUT", `/targets/${id}`, { json: patch }),
    remove: (id: string) => request<void>("DELETE", `/targets/${id}`),
  },

  runs: {
    list: () => request<Run[]>("GET", "/runs"),
    start: (maxMinutes?: number) =>
      request<{ status: string }>("POST", maxMinutes ? `/runs?max_minutes=${maxMinutes}` : "/runs"),
    changes: (id: string) => request<Change[]>("GET", `/runs/${id}/changes`),
    observations: (id: string) => request<Observation[]>("GET", `/runs/${id}/observations`),
    exportFile: async (id: string, format: "csv" | "json") => {
      const response = await send("GET", `/runs/${id}/export?format=${format}`);
      return response.blob();
    },
    sendToDefectDojo: (id: string) => request<unknown>("POST", `/runs/${id}/defectdojo`),
    importResults: (format: FileFormat, content: string) =>
      request<{ run_id: string }>("POST", `/results/import?format=${format}`, { text: content }),
  },

  signatures: {
    list: () => request<SignatureList>("GET", "/signatures"),
    add: (yaml: string) => request<{ id: string; active_signatures: number }>("POST", "/signatures", { json: { yaml } }),
    remove: (id: string) => request<void>("DELETE", `/signatures/${id}`),
  },

  users: {
    list: () => request<User[]>("GET", "/users"),
    create: (username: string, password: string, role: Role) =>
      request<{ id: string }>("POST", "/users", { json: { username, password, role } }),
    changeRole: (id: string, role: Role) => request<void>("PUT", `/users/${id}`, { json: { role } }),
    remove: (id: string) => request<void>("DELETE", `/users/${id}`),
  },
};
