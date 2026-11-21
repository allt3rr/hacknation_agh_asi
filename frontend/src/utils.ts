import type { FileFormat, RunStats } from "./types";

/** Klasy przycisku drugorzędnego (obramowany, bez tła). */
export const BTN_SECONDARY = "border border-line bg-transparent px-2.5 py-1 text-fg";

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** "2026-11-21T22:15:03+00:00" -> "2026-11-21 22:15" */
export function formatDate(iso: string): string {
  return iso.slice(0, 16).replace("T", " ");
}

export function fileFormat(fileName: string): FileFormat {
  const extension = fileName.split(".").pop()?.toLowerCase();
  if (extension === "csv" || extension === "json") {
    return extension;
  }
  return "txt";
}

export function downloadBlob(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}

export function parseRunStats(json: string | null): RunStats {
  if (!json) {
    return {};
  }
  try {
    return JSON.parse(json) as RunStats;
  } catch {
    return {};
  }
}
