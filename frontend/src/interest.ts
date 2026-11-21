// Ocena "ciekawości" usługi dla analityka (0-100). Heurystyka po stronie interfejsu:
// waga kategorii detekcji × pewność, plus priorytet nadany ręcznie w adnotacji.

import type { Annotation, Observation } from "./types";

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

export function interestScore(observation: Observation, annotation?: Annotation): number {
  const detections = observation.detections.reduce(
    (sum, d) => sum + ((CATEGORY_WEIGHTS[d.category] ?? 5) * d.confidence) / 100,
    0,
  );
  const severity = SEVERITY_BONUS[annotation?.severity ?? ""] ?? 0;
  return Math.min(100, Math.round(detections + severity));
}

export function interestLabel(score: number): string {
  if (score >= 60) return "wysoka";
  if (score >= 30) return "średnia";
  return "niska";
}

export const INTEREST_HINT =
  "Ocena 0-100: panel administracyjny 40, staging 35, IoT/interesujące 30, CMS 15, inne 5-10 (× pewność detekcji) plus priorytet z adnotacji.";
