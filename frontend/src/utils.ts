import type { Coverage, FileFormat } from "./types";

/** Klasy przycisku drugorzędnego (obramowany, bez tła). */
export const BTN_SECONDARY = "border border-line bg-transparent px-2.5 py-1 text-fg";

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

export const BADGE = "mr-1 my-px inline-block rounded-full border border-line bg-bg px-2 py-px text-xs";
