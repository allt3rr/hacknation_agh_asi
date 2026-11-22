import type { Coverage, FileFormat, Run, RunStatus, ScheduleEntry, ScheduleWindow } from "./types";

/** Klasy przycisku drugorzędnego (obramowany, bez tła). */
export const BTN_SECONDARY = "border border-line bg-surface px-2.5 py-1 text-fg shadow-none hover:border-accent hover:text-accent";

export const STATUS_LABELS: Record<RunStatus, string> = {
  queued: "w kolejce",
  running: "w toku",
  done: "zakończony",
  partial: "częściowy",
  failed: "błąd",
  cancelled: "anulowany",
};

/** 3725400 ms -> "1 h 2 min 5 s" */
export function formatDuration(ms: number | null): string {
  if (ms === null) return "";
  const total = Math.round(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return [h && `${h} h`, (h || m) && `${m} min`, `${s} s`].filter(Boolean).join(" ");
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** "2026-11-21T22:15:03.123Z" -> "2026-11-21 22:15" (czas lokalny przeglądarki) */
export function formatDate(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 16).replace("T", " ");
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function fileFormat(fileName: string): FileFormat {
  const extension = fileName.split(".").pop()?.toLowerCase();
  if (extension === "csv" || extension === "json") {
    return extension;
  }
  return "text";
}

export function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}

export function coverageText(c: Coverage): string {
  return [
    c.planned !== undefined && `cele: ${c.scanned ?? 0}/${c.planned}`,
    c.live_hosts !== undefined && `hosty: ${c.live_hosts}`,
    c.services !== undefined && `usługi: ${c.services}`,
    c.pending ? `zaległe: ${c.pending}` : null,
    c.failed ? `nieudane: ${c.failed}` : null,
  ]
    .filter(Boolean)
    .join(", ");
}

export const BADGE = "mr-1 my-px inline-flex items-center whitespace-nowrap rounded-full border border-accent/25 bg-accent/10 px-2 py-px text-xs font-medium text-fg";

export interface Progress {
  /** 0–100 albo null, gdy plan nie jest jeszcze znany (`hosts_total = 0`). */
  percent: number | null;
  /** Liniowe oszacowanie pozostałego czasu; null przed pierwszą zakończoną podgrupą. */
  etaMs: number | null;
  elapsedMs: number;
}

export function progressEta(run: Pick<Run, "hosts_total" | "hosts_done" | "started_at" | "created_at">, now: number): Progress {
  const { hosts_total: total, hosts_done: done } = run;
  const elapsedMs = Math.max(0, now - new Date(run.started_at ?? run.created_at).getTime());
  if (total <= 0) return { percent: null, etaMs: null, elapsedMs };
  const percent = Math.min(100, Math.floor((done / total) * 100));
  const etaMs = done > 0 ? Math.round((elapsedMs * Math.max(0, total - done)) / done) : null;
  return { percent, etaMs, elapsedMs };
}

if (import.meta.env.DEV) {
  const at = (total: number, done: number) => progressEta({ hosts_total: total, hosts_done: done, started_at: "2026-01-01T00:00:00Z", created_at: "" }, Date.parse("2026-01-01T00:01:00Z"));
  console.assert(at(0, 0).percent === null && at(0, 0).etaMs === null, "progressEta 0/0");
  console.assert(at(10, 0).percent === 0 && at(10, 0).etaMs === null, "progressEta 0/N");
  console.assert(at(10, 5).percent === 50 && at(10, 5).etaMs === 60_000, "progressEta N/2N");
  console.assert(at(10, 10).percent === 100 && at(10, 10).etaMs === 0, "progressEta N/N");
}

/** „Zaznacz wszystkie” dla wyników wyszukiwania: gdy wszystkie są zaznaczone, odznacza tylko je; elementów spoza nie rusza. */
export function toggleAll(selected: ReadonlySet<string>, filteredIds: readonly string[]): Set<string> {
  const next = new Set(selected);
  const allOn = filteredIds.length > 0 && filteredIds.every((id) => next.has(id));
  for (const id of filteredIds) {
    if (allOn) next.delete(id);
    else next.add(id);
  }
  return next;
}

if (import.meta.env.DEV) {
  const s = (...ids: string[]) => new Set(ids);
  const eq = (a: Set<string>, b: string[]) => a.size === b.length && b.every((x) => a.has(x));
  console.assert(eq(toggleAll(s("x"), ["a", "b"]), ["x", "a", "b"]), "toggleAll: dodaje wyniki, zostawia x");
  console.assert(eq(toggleAll(s("x", "a"), ["a", "b"]), ["x", "a", "b"]), "toggleAll: częściowe → wszystkie");
  console.assert(eq(toggleAll(s("x", "a", "b"), ["a", "b"]), ["x"]), "toggleAll: wszystkie → odznacza tylko wyniki");
  console.assert(eq(toggleAll(s("x"), []), ["x"]), "toggleAll: puste wyniki bez zmian");
}

const DAY_LABELS: Record<string, string> = { mon: "pn", tue: "wt", wed: "śr", thu: "cz", fri: "pt", sat: "sb", sun: "nd" };

/** Okna pozycji harmonogramu jednym ciągiem; brak okien = „bez ograniczeń”. */
export function formatWindows(windows: ScheduleWindow[]): string {
  if (!windows.length) return "bez ograniczeń";
  return windows.map((w) => `${w.days.length ? w.days.map((d) => DAY_LABELS[d] ?? d).join(",") : "codziennie"} ${w.start}–${w.end}`).join("; ");
}

/** Najwcześniejszy kolejny start pozycji jak w `is_due`: start jej ostatniego przebiegu + N h (okna mogą go przesunąć). */
export function nextScheduledStart(s: ScheduleEntry, now = Date.now()): string {
  if (!s.enabled) return "wyłączona";
  if (!s.last_run_at || s.last_status === "partial" || s.last_status === "failed") return "przy najbliższym sprawdzeniu";
  const at = new Date(s.last_run_at).getTime() + s.every_hours * 3_600_000;
  return at > now ? formatDate(new Date(at).toISOString()) : "przy najbliższym sprawdzeniu";
}
