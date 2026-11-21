// Ocena "ciekawości" usługi dla analityka (0-100). Heurystyka po stronie interfejsu:
// waga kategorii detekcji × pewność, plus priorytet nadany w korekcie wyniku (severity).

import type { ResultRow } from "./types";

const CATEGORY_WEIGHTS: Record<string, number> = {
  admin_panel: 40,
  staging: 35,
  iot: 30,
  interesting: 30,
  cms: 15,
  application: 10,
  framework: 10,
  server: 5,
};

const SEVERITY_BONUS: Record<string, number> = { critical: 40, high: 30, medium: 20, low: 10 };

export function interestScore(row: ResultRow): number {
  const detections = row.technologies.reduce((sum, d) => sum + ((CATEGORY_WEIGHTS[d.category] ?? 5) * d.confidence) / 100, 0);
  return Math.min(100, Math.round(detections + (SEVERITY_BONUS[row.severity ?? ""] ?? 0)));
}

export function interestLabel(score: number): string {
  if (score >= 60) return "wysoka";
  if (score >= 30) return "średnia";
  return "niska";
}

export const INTEREST_HINT =
  "Ocena 0-100: panel administracyjny 40, staging 35, IoT/interesujące 30, CMS 15, inne 5-10 (× pewność detekcji) plus priorytet (severity) z korekty.";
