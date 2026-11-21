import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { ChangeTable } from "../components/ChangeTable";
import { DataTable } from "../components/DataTable";
import { FilePicker } from "../components/FilePicker";
import { ObservationTable } from "../components/ObservationTable";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { Change, Page, ResultRow, Run, RunStatus, Session } from "../types";
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
const REFRESH_MS = 5000;

type Details =
  | { kind: "services"; run: Run; offset: number; page: Page<ResultRow> }
  | { kind: "changes"; run: Run; page: Page<Change> };

export function RunsPage({ session }: { session: Session }) {
  const { data: runs, error, reload } = useApiData(api.runs.list);
  const { info, error: showError, run } = useNotice();
  const [details, setDetails] = useState<Details | null>(null);
  const detailsHeading = useRef<HTMLHeadingElement>(null);
  const scanActive = runs?.some((r) => r.status === "running" || r.status === "queued") ?? false;

  // Lista odświeża się sama, dopóki skan czeka lub trwa.
  useEffect(() => {
    if (!scanActive) return;
    const timer = setInterval(reload, REFRESH_MS);
    return () => clearInterval(timer);
  }, [scanActive, reload]);

  // Po otwarciu innych szczegółów (inny przebieg lub rodzaj) fokus i widok przechodzą na nagłówek panelu.
  const detailsId = details ? `${details.kind}-${details.run.id}` : null;
  useEffect(() => {
    if (!detailsId) return;
    detailsHeading.current?.focus();
    detailsHeading.current?.scrollIntoView({ block: "start" });
  }, [detailsId]);

  const startScan = () =>
    run(async () => {
      await api.runs.start();
      info("Skan uruchomiony. Lista odświeża się co 5 s, dopóki skan trwa.");
      await reload();
    });

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

  const exportRun = (r: Run, format: "csv" | "json") =>
    run(async () => downloadBlob(await api.runs.exportFile(r.id, format), `asi-${r.id}.${format}`));

  const sendToDefectDojo = (r: Run) =>
    run(async () => {
      const res = await api.runs.sendToDefectDojo(r.id);
      info(`Wysłano do DefectDojo findingi: ${res.findings}`);
    });

  return (
    <>
      {(can(session, "scans.run") || can(session, "targets.create")) && (
        <Card title="Nowy przebieg">
          {can(session, "scans.run") && (
            <div className="my-2 flex flex-wrap items-center gap-2">
              <button onClick={startScan} disabled={scanActive}>
                {scanActive ? "Skan w toku..." : "Uruchom skan"}
              </button>
              <span className="text-muted">Jeśli w zakładce Harmonogram są okna czasowe, skan można uruchomić tylko w oknie.</span>
            </div>
          )}
          {can(session, "targets.create") && (
            <div className="my-2 flex flex-wrap items-center gap-2">
              <span className="text-muted">Import wyników skanu z pliku JSON lub CSV w formacie eksportu ASI:</span>
              <FilePicker accept=".csv,.json" label="Plik z wynikami skanu" buttonLabel="Importuj" onSubmit={importResults} />
            </div>
          )}
        </Card>
      )}

      <Card title="Przebiegi" actions={<button className={BTN_SECONDARY} onClick={reload}>Odśwież</button>}>
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
            { header: "Start", render: (r) => formatDate(r.started_at ?? r.created_at) },
            { header: "Rodzaj", render: (r) => (r.kind === "import" ? "import" : "skan") },
            {
              header: "Status",
              render: (r) => (
                <>
                  <span className={`font-medium ${STATUS_COLORS[r.status]}`}>{STATUS_LABELS[r.status] ?? r.status}</span>
                  {r.reason && <div className="text-muted">{r.reason}</div>}
                </>
              ),
            },
            { header: "Czas trwania", render: (r) => formatDuration(r.duration_ms) },
            { header: "Pokrycie", render: (r) => <span className="text-muted">{coverageText(r.coverage)}</span> },
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
                        <button className={BTN_SECONDARY} aria-label={`Zmiany w przebiegu ${name}`} onClick={() => showChanges(r)}>Zmiany</button>
                        <button className={BTN_SECONDARY} aria-label={`Usługi w przebiegu ${name}`} onClick={() => showServices(r)}>Usługi</button>
                        {can(session, "export") && (
                          <>
                            <button className={BTN_SECONDARY} aria-label={`Eksport przebiegu ${name} do JSON`} onClick={() => exportRun(r, "json")}>JSON</button>
                            <button className={BTN_SECONDARY} aria-label={`Eksport przebiegu ${name} do CSV`} onClick={() => exportRun(r, "csv")}>CSV</button>
                          </>
                        )}
                        {can(session, "integrations.export") && (
                          <button className={BTN_SECONDARY} aria-label={`Wyślij przebieg ${name} do DefectDojo`} onClick={() => sendToDefectDojo(r)}>DefectDojo</button>
                        )}
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
              : `Zmiany (${details.page.total}): ${formatDate(details.run.started_at)}`
          }
          headingRef={detailsHeading}
          actions={<button className={BTN_SECONDARY} onClick={() => setDetails(null)}>Zamknij</button>}
        >
          {details.kind === "services" ? (
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
                <p className="my-2 text-muted">Pokazano {details.page.items.length} z {details.page.total} (pełna lista w eksporcie).</p>
              )}
            </>
          )}
        </Card>
      )}
    </>
  );
}
