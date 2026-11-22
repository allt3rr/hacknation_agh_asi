// Raport PDF przebiegu: HTML w ukrytym iframe + okno druku przeglądarki ("Zapisz jako PDF").
// Bez biblioteki PDF: polskie znaki i łamanie tabel na strony robi przeglądarka.

import { api } from "./api";
import { KIND_LABELS } from "./components/ChangeTable";
import { INTEREST_HINT, interestLabel, interestScore } from "./interest";
import type { Change, Page, ResultRow, Run, Session } from "./types";
import { STATUS_LABELS, coverageText, formatDate, formatDuration } from "./utils";

const LEVELS = [
  { label: "wysoka", title: "Zagrożenie wysokie", color: "#c81e1e" },
  { label: "średnia", title: "Zagrożenie średnie", color: "#9a4a05" },
  { label: "niska", title: "Zagrożenie niskie", color: "#166534" },
] as const;

// shortcut: pobiera wszystkie strony do pamięci przeglądarki; przy setkach tysięcy usług potrzebny raport po stronie backendu.
async function fetchAll<T>(load: (offset: number) => Promise<Page<T>>): Promise<T[]> {
  const items: T[] = [];
  for (;;) {
    const page = await load(items.length);
    items.push(...page.items);
    if (!page.items.length || items.length >= page.total) return items;
  }
}

/** Dane ze skanu (tytuły stron, bannery) są niezaufane: wszystko przez escape. */
export function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function serviceRow(o: ResultRow, score: number): string {
  const tech = o.technologies.map((d) => `${d.name}${d.version ? ` ${d.version}` : ""}`).join(", ");
  const product = [o.product, o.version].filter(Boolean).join(" ");
  return `<tr><td class="num">${score}</td><td>${esc(o.ip)}${o.hostname ? `<div class="sub">${esc(o.hostname)}</div>` : ""}</td>
<td>${o.port}/${esc(o.proto)}</td><td>${esc(o.service)}</td><td>${esc(product)}</td><td>${esc(tech)}</td>
<td>${esc(o.http?.title)}</td><td>${esc(o.severity)}</td></tr>`;
}

export function buildReportHtml(run: Run, session: Session, services: ResultRow[], changes: Change[], now = new Date()): string {
  const scored = services.map((o) => ({ o, score: interestScore(o) })).sort((a, b) => b.score - a.score);
  const groups = LEVELS.map((l) => ({ ...l, rows: scored.filter((s) => interestLabel(s.score) === l.label) }));
  const generated = formatDate(now.toISOString());
  const started = formatDate(run.started_at ?? run.created_at);

  const meta: [string, string][] = [
    ["Rodzaj", run.kind === "import" ? "import" : "skan"],
    ["Status", `${STATUS_LABELS[run.status] ?? run.status}${run.reason ? ` (${run.reason})` : ""}`],
    ["Start", started],
    ["Koniec", formatDate(run.finished_at)],
    ["Czas trwania", formatDuration(run.duration_ms)],
    ["Pokrycie", coverageText(run.coverage)],
    ["Identyfikator", run.id],
    ["Wygenerował", session.username],
  ];

  const sections = groups
    .map((g) =>
      g.rows.length
        ? `<h3 style="color:${g.color}">${g.title} (${g.rows.length})</h3>
<table class="svc"><thead><tr><th>Ocena</th><th>Host</th><th>Port</th><th>Usługa</th><th>Produkt</th><th>Technologie</th><th>Tytuł HTTP</th><th>Priorytet</th></tr></thead>
<tbody>${g.rows.map((s) => serviceRow(s.o, s.score)).join("")}</tbody></table>`
        : "",
    )
    .join("");

  const changeTable = changes.length
    ? `<table><thead><tr><th>Typ</th><th>Usługa / host</th><th>Pole</th><th>Przed</th><th>Po</th></tr></thead><tbody>${changes
        .map(
          (c) =>
            `<tr><td>${esc(KIND_LABELS[c.kind] ?? c.kind)}</td><td>${esc(c.entity_key)}</td><td>${esc(c.field)}</td><td>${esc(c.before)}</td><td>${esc(c.after)}</td></tr>`,
        )
        .join("")}</tbody></table>`
    : `<p class="sub">Brak zmian względem poprzedniego przebiegu.</p>`;

  return `<!doctype html><html lang="pl"><head><meta charset="utf-8">
<title>Raport ASI ${esc(started)}</title>
<style>
  @page { size: A4 landscape; margin: 14mm; }
  body { font: 10pt/1.4 system-ui, "Segoe UI", Arial, sans-serif; color: #0f172a; margin: 0; }
  header { border-bottom: 3px solid #4f46e5; padding-bottom: 8px; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: flex-end; }
  h1 { font-size: 20pt; margin: 0; color: #4f46e5; }
  h1 small { display: block; font-size: 11pt; color: #556074; font-weight: 500; }
  h2 { font-size: 13pt; margin: 18px 0 6px; border-bottom: 1px solid #e2e8f0; padding-bottom: 3px; }
  h3 { font-size: 11pt; margin: 14px 0 4px; }
  .gen { text-align: right; color: #556074; }
  .gen b { color: #0f172a; font-size: 11pt; }
  table { width: 100%; border-collapse: collapse; margin: 4px 0 8px; }
  thead { display: table-header-group; }
  tr { page-break-inside: avoid; }
  th { background: #eef2fa; text-align: left; font-weight: 600; }
  th, td { border: 1px solid #e2e8f0; padding: 3px 6px; vertical-align: top; word-break: break-word; }
  tbody tr:nth-child(even) td { background: #f8fafc; }
  th, .svc td:nth-child(-n+4) { white-space: nowrap; }
  .num { text-align: right; font-weight: 600; }
  .sub { color: #556074; font-size: 9pt; }
  .meta td:first-child { width: 22%; color: #556074; }
  .cards { display: flex; gap: 10px; margin: 6px 0; }
  .card { flex: 1; border: 1px solid #e2e8f0; border-top: 4px solid; border-radius: 6px; padding: 6px 10px; }
  .card b { font-size: 18pt; display: block; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
</style></head><body>
<header>
  <h1>Raport z przebiegu skanu<small>Attack Surface Intelligence · przebieg z ${esc(started)}</small></h1>
  <div class="gen">Wygenerowano<br><b>${esc(generated.slice(0, 10))}</b> godz. <b>${esc(generated.slice(11))}</b></div>
</header>
<h2>Przebieg</h2>
<table class="meta"><tbody>${meta.map(([k, v]) => `<tr><td>${k}</td><td>${esc(v)}</td></tr>`).join("")}</tbody></table>
<h2>Podsumowanie zagrożeń</h2>
<div class="cards">
  <div class="card" style="border-top-color:#4f46e5">Usługi<b>${services.length}</b></div>
  ${groups.map((g) => `<div class="card" style="border-top-color:${g.color}">${g.title}<b style="color:${g.color}">${g.rows.length}</b></div>`).join("")}
  <div class="card" style="border-top-color:#0891b2">Zmiany<b>${changes.length}</b></div>
</div>
<h2>Usługi według poziomu zagrożenia</h2>
${sections || `<p class="sub">Brak usług w tym przebiegu.</p>`}
<h2>Zmiany względem poprzedniego przebiegu</h2>
${changeTable}
<h2>Legenda oceny</h2>
<p>${esc(INTEREST_HINT)} Poziomy: wysokie ≥ 60, średnie 30–59, niskie &lt; 30.</p>
</body></html>`;
}

/** Drukuje raport z ukrytego iframe na tej samej stronie: bez nowej karty i bez about:blank. */
export async function printRunReport(run: Run, session: Session): Promise<void> {
  const [services, changes] = await Promise.all([
    fetchAll((offset) => api.runs.observations(run.id, offset)),
    fetchAll((offset) => api.runs.changes(run.id, offset)),
  ]);
  const frame = document.createElement("iframe");
  frame.setAttribute("aria-hidden", "true");
  frame.style.cssText = "position:fixed;width:0;height:0;border:0;visibility:hidden";
  frame.srcdoc = buildReportHtml(run, session, services, changes);
  frame.onload = () => {
    const win = frame.contentWindow!;
    // Tytuł iframe podpowiada nazwę pliku PDF w oknie druku.
    const pageTitle = document.title;
    document.title = win.document.title;
    win.addEventListener("afterprint", () => {
      document.title = pageTitle;
      frame.remove();
    });
    win.focus();
    win.print();
  };
  document.body.appendChild(frame);
}
