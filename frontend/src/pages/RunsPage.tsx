import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { ApiError, api } from "../api";
import { Card } from "../components/Card";
import { ChangeTable } from "../components/ChangeTable";
import { DataTable } from "../components/DataTable";
import { FilePicker } from "../components/FilePicker";
import { ObservationTable } from "../components/ObservationTable";
import { ScanProgress } from "../components/ScanProgress";
import { TargetPicker } from "../components/TargetPicker";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { SEVERITIES, SEVERITY_COLORS, VULN_STATE_LABELS, VulnTable } from "../components/VulnTable";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { Change, Page, ResultRow, Run, RunStatus, Session, Severity, Target, VulnMode, VulnPage } from "../types";
import { BTN_SECONDARY, STATUS_LABELS, coverageText, downloadBlob, fileFormat, formatDate, formatDuration } from "../utils";

const STATUS_COLORS: Record<RunStatus, string> = {
  queued: "",
  running: "text-accent",
  done: "text-green",
  partial: "text-orange",
  failed: "text-red",
  cancelled: "text-muted",
};

const PAGE_SIZE = 100;
// bez scans.run lista wyboru nie jest pokazywana, więc nie pobieramy celów (stabilna referencja dla useApiData)
const noTargets = () => Promise.resolve<Target[]>([]);
const REFRESH_MS = 1000;
// Jak długo po akcji (skan, decyzja o CVE, wysyłka) lista czeka na wynik wysyłki do DefectDojo.
const EXPORT_WAIT_MS = 2 * 60 * 1000;

/** Popup (Sonner z shadcn) o przesłaniu wyników przebiegu do DefectDojo albo o błędzie wysyłki. */
function notifyExport(r: Run) {
  const e = r.dd_export;
  if (!e) return;
  const run = formatDate(r.started_at ?? r.created_at);
  if (e.error) {
    toast.error("Wysyłka do DefectDojo nieudana", { description: `Skan z ${run}: ${e.error}`, duration: 12000 });
    return;
  }
  const what = e.content === "all" ? "Wyniki skanu z opisem CVE" : "Wyniki skanu (bez CVE)";
  const failed = e.failed?.length ? ` Nieudane IP: ${e.failed.join(", ")}.` : "";
  toast.success("Przesłano do DefectDojo", {
    description: `${what} ze skanu z ${run}: findingi ${e.findings ?? 0}, engagementy ${e.engagements ?? 0}.${failed}`,
  });
}

type Details =
  | { kind: "services"; run: Run; offset: number; page: Page<ResultRow> }
  | { kind: "changes"; run: Run; page: Page<Change> }
  | { kind: "vulns"; run: Run; offset: number; severity?: Severity; page: VulnPage };

export function RunsPage({ session }: { session: Session }) {
  const { data: runs, error, reload } = useApiData(api.runs.list);
  const canRun = can(session, "scans.run");
  const { data: targets } = useApiData(canRun ? api.targets.list : noTargets);
  const { info, error: showError, run } = useNotice();
  const [details, setDetails] = useState<Details | null>(null);
  const detailsHeading = useRef<HTMLHeadingElement>(null);
  const scanActive = runs?.some((r) => r.status === "running" || r.status === "queued") ?? false;
  const checkActive = runs?.some((r) => r.vuln_state === "running") ?? false;
  const running = runs?.find((r) => r.status === "running");
  const awaiting = canRun ? (runs ?? []).filter((r) => r.vuln_state === "pending_decision") : [];
  // przebiegi, na których wysyłkę do DefectDojo czekamy (id → termin)
  const [watching, setWatching] = useState<Record<string, number>>({});
  const watch = (id: string) => setWatching((w) => ({ ...w, [id]: Date.now() + EXPORT_WAIT_MS }));
  const waitingExport = Object.keys(watching).length > 0;
  // ostatnio widziany czas wysyłki per przebieg; null przed pierwszym odczytem (bez popupów za stare wysyłki)
  const seenExports = useRef<Map<string, string | null> | null>(null);

  // Lista odświeża się sama, dopóki skan lub sprawdzanie podatności trwa albo czekamy na wysyłkę do DefectDojo.
  useEffect(() => {
    if (!scanActive && !checkActive && !waitingExport) return;
    const timer = setInterval(reload, REFRESH_MS);
    return () => clearInterval(timer);
  }, [scanActive, checkActive, waitingExport, reload]);

  // Nowy wynik wysyłki do DefectDojo → popup; obserwacja trwa, dopóki przebieg pracuje, potem do terminu.
  useEffect(() => {
    if (!runs) return;
    const seen = seenExports.current;
    const done = new Set<string>();
    for (const r of runs) {
      const at = r.dd_export?.at ?? null;
      if (seen && at && seen.get(r.id) !== at) {
        notifyExport(r);
        done.add(r.id);
      }
    }
    seenExports.current = new Map(runs.map((r) => [r.id, r.dd_export?.at ?? null]));
    setWatching((w) => {
      const now = Date.now();
      const next: Record<string, number> = {};
      for (const [id, until] of Object.entries(w)) {
        if (done.has(id)) continue;
        const r = runs.find((x) => x.id === id);
        const busy = r && (r.status === "running" || r.status === "queued" || r.vuln_state === "running");
        if (busy) next[id] = now + EXPORT_WAIT_MS;
        else if (until > now) next[id] = until;
      }
      return Object.keys(next).length === Object.keys(w).length && Object.keys(w).every((id) => next[id] === w[id]) ? w : next;
    });
  }, [runs]);

  // Po otwarciu innych szczegółów (inny przebieg lub rodzaj) fokus i widok przechodzą na nagłówek panelu.
  const detailsId = details ? `${details.kind}-${details.run.id}` : null;
  useEffect(() => {
    if (!detailsId) return;
    detailsHeading.current?.focus();
    detailsHeading.current?.scrollIntoView({ block: "start" });
  }, [detailsId]);

  const startScan = async (ids: string[], vulnCheck: VulnMode) => {
    let ok = false;
    await run(async () => {
      const { run_id } = await api.runs.start(ids, vulnCheck);
      watch(run_id);
      ok = true;
      info(`Skan uruchomiony na celach: ${ids.length}`);
      await reload();
    });
    return ok;
  };

  const cancel = (r: Run) =>
    run(async () => {
      if (!confirm("Przerwać trwający skan? Wynik nie zostanie zapisany.")) return;
      await api.runs.cancel(r.id);
      await reload();
    });

  const importResults = (file: File) =>
    run(async () => {
      const res = await api.runs.importResults(fileFormat(file.name), await file.text());
      info(`Zaimportowano usługi: ${res.observations}, wykryte zmiany: ${res.changes}`);
      await reload();
    });

  const showServices = (r: Run, offset = 0) =>
    run(async () => setDetails({ kind: "services", run: r, offset, page: await api.runs.observations(r.id, offset) }));

  const showChanges = (r: Run) => run(async () => setDetails({ kind: "changes", run: r, page: await api.runs.changes(r.id) }));

  const [pdfBusy, setPdfBusy] = useState<string | null>(null);
  const downloadReport = (r: Run) =>
    run(async () => {
      setPdfBusy(r.id);
      try {
        const { blob, name } = await api.runs.reportPdf(r.id);
        downloadBlob(blob, name);
      } finally {
        setPdfBusy(null);
      }
    });

  const exportRun = (r: Run, format: "csv" | "json") =>
    run(async () => downloadBlob(await api.runs.exportFile(r.id, format), `asi-${r.id}.${format}`));

  const showVulns = (r: Run, offset = 0, severity?: Severity) =>
    run(async () => setDetails({ kind: "vulns", run: r, offset, severity, page: await api.runs.vulnerabilities(r.id, offset, severity) }));

  const checkVulns = (r: Run) =>
    run(async () => {
      await api.runs.startVulnCheck(r.id);
      watch(r.id);
      info("Sprawdzanie podatności uruchomione");
      await reload();
    });

  // popup pokazuje efekt nowego wyniku wysyłki zapisanego w przebiegu (także przy błędzie 502)
  const sendToDefectDojo = (r: Run) =>
    run(async () => {
      watch(r.id);
      try {
        await api.runs.sendToDefectDojo(r.id);
      } catch (e) {
        // 502 (DefectDojo niedostępne) jest zapisane w przebiegu i pokaże je popup; inne błędy pokazujemy od razu
        if (!(e instanceof ApiError && e.status === 502)) throw e;
      } finally {
        await reload();
      }
    });

  const skipVulns = (r: Run) =>
    run(async () => {
      await api.runs.skipVulnCheck(r.id);
      watch(r.id);
      info("Pominięto sprawdzanie CVE. Wyniki skanu trafią do DefectDojo; podatności sprawdzisz później przyciskiem „Sprawdź CVE”.");
      await reload();
    });

  return (
    <>
      {running && <ScanProgress run={running} onCancel={canRun ? () => cancel(running) : undefined} />}

      {canRun && <TargetPicker targets={targets ?? []} busy={scanActive} onStart={startScan} />}

      {awaiting.map((r) => (
        <section key={r.id} role="alert" className="panel mb-3 flex flex-wrap items-center gap-2 border-orange p-3">
          <div className="flex-1">
            <p className="font-medium">
              Skan z {formatDate(r.started_at ?? r.created_at)} zakończony. Sprawdzić podatności (CVE) wykrytych usług?
            </p>
            <ul className="mt-1 list-disc pl-5 text-muted">
              <li>
                <strong>Sprawdź podatności</strong>: po zakończeniu sprawdzania wyniki razem z opisem CVE automatycznie
                trafią do DefectDojo.
              </li>
              <li>
                <strong>Pomiń</strong>: do DefectDojo trafią same wyniki skanu. Podatności możesz sprawdzić później
                przyciskiem „Sprawdź CVE” i przesłać je przyciskiem „CVE → DefectDojo”.
              </li>
            </ul>
          </div>
          <button onClick={() => checkVulns(r)}>Sprawdź podatności</button>
          <button className={BTN_SECONDARY} onClick={() => skipVulns(r)}>
            Pomiń
          </button>
        </section>
      ))}

      <Card
        title={`Przebiegi (${runs?.length ?? 0})`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {can(session, "targets.create") && (
              <FilePicker accept=".csv,.json" label="Import wyników skanu (JSON/CSV, format eksportu ASI)" buttonLabel="Importuj wyniki" onSubmit={importResults} />
            )}
            <button className={BTN_SECONDARY} onClick={reload}>
              Odśwież
            </button>
          </div>
        }
      >
        {error && (
          <p role="alert" className="my-3.5 text-red">
            {error}
          </p>
        )}
        <DataTable
          rows={runs ?? []}
          rowKey={(r) => r.id}
          label="Przebiegi skanów"
          emptyText={runs ? "Brak przebiegów" : "Ładowanie..."}
          columns={[
            { header: "Start", mono: true, render: (r) => formatDate(r.started_at ?? r.created_at) },
            { header: "Rodzaj", render: (r) => (r.kind === "import" ? "import" : "skan") },
            {
              header: "Status",
              title: (r) => [STATUS_LABELS[r.status] ?? r.status, r.reason].filter(Boolean).join(": "),
              render: (r) => (
                <>
                  <span className={`font-medium ${STATUS_COLORS[r.status]}`}>{STATUS_LABELS[r.status] ?? r.status}</span>
                  {r.reason && <div className="text-muted">{r.reason}</div>}
                </>
              ),
            },
            { header: "Czas", mono: true, render: (r) => formatDuration(r.duration_ms) },
            { header: "Pokrycie", mono: true, render: (r) => coverageText(r.coverage) },
            {
              header: "Podatności",
              title: (r) => [VULN_STATE_LABELS[r.vuln_state], r.vuln_reason].filter(Boolean).join(": "),
              render: (r) => (
                <>
                  <span className={r.vuln_state === "failed" ? "text-red" : r.vuln_state === "running" ? "text-accent" : ""}>
                    {VULN_STATE_LABELS[r.vuln_state]}
                  </span>
                  {r.vuln_state === "done" && (
                    <div className="text-muted">
                      CVE: {r.vuln_summary.vulnerabilities ?? 0}, potwierdzone: {r.vuln_summary.confirmed ?? 0}
                      {/* podział według dowodu tylko dla sprawdzeń, które go zapisały */}
                      {r.vuln_summary.version_match !== undefined &&
                        `, dokładna wersja: ${r.vuln_summary.version_match}, niepewne: ${(r.vuln_summary.backport ?? 0) + (r.vuln_summary.conditional ?? 0)}`}
                    </div>
                  )}
                  {r.vuln_reason && <div className="text-muted">{r.vuln_reason}</div>}
                </>
              ),
            },
            {
              header: "",
              render: (r) => {
                const name = formatDate(r.started_at ?? r.created_at);
                return (
                  <div className="flex flex-wrap gap-1">
                    {r.status === "running" ? (
                      can(session, "scans.run") && (
                        <button className={BTN_SECONDARY} aria-label={`Anuluj skan ${name}`} onClick={() => cancel(r)}>
                          Anuluj
                        </button>
                      )
                    ) : (
                      <>
                        {/* Select jako menu akcji: value="" zostawia placeholder, wybór od razu uruchamia akcję */}
                        <Select
                          value=""
                          onValueChange={(v) => (v === "changes" ? showChanges(r) : v === "services" ? showServices(r) : showVulns(r))}
                        >
                          <SelectTrigger aria-label={`Podgląd przebiegu ${name}`}>
                            <SelectValue placeholder="Podgląd" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="changes">Zmiany</SelectItem>
                            <SelectItem value="services">Usługi</SelectItem>
                            {(r.vuln_state === "done" || r.vuln_state === "failed") && <SelectItem value="vulns">CVE</SelectItem>}
                          </SelectContent>
                        </Select>
                        {canRun && (r.status === "done" || r.status === "partial") && r.vuln_state !== "running" && r.vuln_state !== "pending_decision" && (
                          <button className={BTN_SECONDARY} aria-label={`Sprawdź podatności w przebiegu ${name}`} onClick={() => checkVulns(r)}>
                            {r.vuln_state === "done" ? "Sprawdź ponownie CVE" : "Sprawdź CVE"}
                          </button>
                        )}
                        <Select
                          value=""
                          onValueChange={(v) => (v === "dd" ? sendToDefectDojo(r) : v === "pdf" ? downloadReport(r) : exportRun(r, v as "json" | "csv"))}
                        >
                          <SelectTrigger aria-label={`Eksport przebiegu ${name}`} aria-busy={pdfBusy === r.id}>
                            <SelectValue placeholder={pdfBusy === r.id ? "Export…" : "Export"} />
                          </SelectTrigger>
                          <SelectContent>
                            {r.vuln_state === "done" && can(session, "integrations.export") && (
                              <SelectItem value="dd" title="Wyślij info z wynikami CVE do DefectDojo (engagement per IP)">
                                CVE → DefectDojo
                              </SelectItem>
                            )}
                            {can(session, "export") && (
                              <>
                                <SelectItem value="json">JSON</SelectItem>
                                <SelectItem value="csv">CSV</SelectItem>
                              </>
                            )}
                            <SelectItem value="pdf" disabled={r.status === "queued" || pdfBusy !== null}>
                              PDF
                            </SelectItem>
                          </SelectContent>
                        </Select>
                      </>
                    )}
                  </div>
                );
              },
            },
          ]}
        />
      </Card>

      {details && (
        <Card
          title={
            details.kind === "services"
              ? `Usługi (${details.page.total}): ${formatDate(details.run.started_at)}`
              : details.kind === "vulns"
                ? `Podatności (${details.page.total}): ${formatDate(details.run.started_at)}`
                : `Zmiany (${details.page.total}): ${formatDate(details.run.started_at)}`
          }
          headingRef={detailsHeading}
          actions={<button className={BTN_SECONDARY} onClick={() => setDetails(null)}>Zamknij</button>}
        >
          {details.kind === "vulns" ? (
            <>
              <div className="my-2 flex flex-wrap items-center gap-2">
                <label className="flex items-center gap-1 text-xs text-muted">
                  Severity
                  <select
                    value={details.severity ?? ""}
                    onChange={(e) => showVulns(details.run, 0, (e.target.value || undefined) as Severity | undefined)}
                  >
                    <option value="">wszystkie</option>
                    {SEVERITIES.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </label>
                {SEVERITIES.map((s) => (
                  <span key={s} className={`mono text-xs ${SEVERITY_COLORS[s]}`}>
                    {s}: {details.page.summary.by_severity[s] ?? 0}
                  </span>
                ))}
                <span className="text-xs text-muted">
                  potwierdzone: {details.page.summary.confirmed}, usługi bez wersji: {details.page.summary.unidentified ?? 0}
                </span>
              </div>
              <VulnTable rows={details.page.items} label={`Podatności w przebiegu ${formatDate(details.run.started_at)}`} />
              <div className="my-2 flex items-center gap-2">
                <button
                  className={BTN_SECONDARY}
                  disabled={details.offset === 0}
                  onClick={() => showVulns(details.run, Math.max(0, details.offset - PAGE_SIZE), details.severity)}
                >
                  Poprzednie
                </button>
                <span className="text-muted">
                  {details.page.total ? details.offset + 1 : 0}–{details.offset + details.page.items.length} z {details.page.total}
                </span>
                <button
                  className={BTN_SECONDARY}
                  disabled={details.offset + PAGE_SIZE >= details.page.total}
                  onClick={() => showVulns(details.run, details.offset + PAGE_SIZE, details.severity)}
                >
                  Następne
                </button>
              </div>
            </>
          ) : details.kind === "services" ? (
            <>
              <ObservationTable
                rows={details.page.items}
                editable={can(session, "data.update")}
                onChanged={() => showServices(details.run, details.offset)}
                onError={(m) => showError(new Error(m))}
              />
              <div className="my-2 flex items-center gap-2">
                <button className={BTN_SECONDARY} disabled={details.offset === 0} onClick={() => showServices(details.run, Math.max(0, details.offset - PAGE_SIZE))}>
                  Poprzednie
                </button>
                <span className="text-muted">
                  {details.page.total ? details.offset + 1 : 0}–{details.offset + details.page.items.length} z {details.page.total}
                </span>
                <button
                  className={BTN_SECONDARY}
                  disabled={details.offset + PAGE_SIZE >= details.page.total}
                  onClick={() => showServices(details.run, details.offset + PAGE_SIZE)}
                >
                  Następne
                </button>
              </div>
            </>
          ) : (
            <>
              <ChangeTable changes={details.page.items} label={`Zmiany w przebiegu ${formatDate(details.run.started_at)}`} />
              {details.page.total > details.page.items.length && (
                <p className="my-2 text-muted">
                  {details.page.items.length}/{details.page.total}, pełna lista w eksporcie
                </p>
              )}
            </>
          )}
        </Card>
      )}
    </>
  );
}
