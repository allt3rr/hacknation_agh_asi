import { useState } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { ChangeTable } from "../components/ChangeTable";
import { DataTable } from "../components/DataTable";
import { FilePicker } from "../components/FilePicker";
import { NoticeBar } from "../components/NoticeBar";
import { ObservationTable } from "../components/ObservationTable";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { Change, Page, ResultRow, Run, RunStatus, Session } from "../types";
import { BTN_SECONDARY, coverageText, downloadBlob, fileFormat, formatDate } from "../utils";

const STATUS_COLORS: Record<RunStatus, string> = {
  queued: "",
  running: "text-accent",
  done: "text-green",
  partial: "text-orange",
  failed: "text-red",
  cancelled: "text-muted",
};

const PAGE_SIZE = 100;

type Details =
  | { kind: "services"; run: Run; offset: number; page: Page<ResultRow> }
  | { kind: "changes"; run: Run; page: Page<Change> };

export function RunsPage({ session }: { session: Session }) {
  const { data: runs, error, reload } = useApiData(api.runs.list);
  const { notice, info, error: showError, run } = useNotice();
  const [details, setDetails] = useState<Details | null>(null);

  const startScan = () =>
    run(async () => {
      await api.runs.start();
      info("Skan uruchomiony. Odśwież listę, aby zobaczyć postęp.");
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
      info(`Zaimportowano ${res.observations} usług, zmian: ${res.changes}`);
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
      info(`Wysłano do DefectDojo: ${res.findings} findingów`);
    });

  return (
    <>
      <NoticeBar notice={notice} />

      {(can(session, "scans.run") || can(session, "targets.create")) && (
        <Card title="Nowy przebieg">
          {can(session, "scans.run") && (
            <div className="my-2 flex flex-wrap items-center gap-2">
              <button onClick={startScan}>Uruchom skan</button>
              <span className="text-muted">Okna czasowe, porty i limity tempa ustawia konfiguracja backendu.</span>
            </div>
          )}
          {can(session, "targets.create") && (
            <div className="my-2 flex flex-wrap items-center gap-2">
              <span className="text-muted">Import wyników (JSON/CSV w formacie eksportu):</span>
              <FilePicker accept=".csv,.json" buttonLabel="Importuj" onSubmit={importResults} />
            </div>
          )}
        </Card>
      )}

      <Card title="Przebiegi" actions={<button className={BTN_SECONDARY} onClick={reload}>Odśwież</button>}>
        {error && <p className="my-3.5 text-red">{error}</p>}
        <DataTable
          rows={runs ?? []}
          rowKey={(r) => r.id}
          columns={[
            { header: "Start", render: (r) => formatDate(r.started_at ?? r.created_at) },
            { header: "Rodzaj", render: (r) => (r.kind === "import" ? "import" : "skan") },
            {
              header: "Status",
              render: (r) => (
                <>
                  <span className={STATUS_COLORS[r.status]}>{r.status}</span>
                  {r.reason && <div className="text-muted">{r.reason}</div>}
                </>
              ),
            },
            { header: "Czas [s]", render: (r) => (r.duration_ms != null ? (r.duration_ms / 1000).toFixed(1) : "") },
            { header: "Pokrycie", render: (r) => <span className="text-muted">{coverageText(r.coverage)}</span> },
            {
              header: "",
              render: (r) => (
                <div className="flex flex-wrap gap-1">
                  {r.status === "running" ? (
                    can(session, "scans.run") && (
                      <button className={BTN_SECONDARY} onClick={() => cancel(r)}>
                        Anuluj
                      </button>
                    )
                  ) : (
                    <>
                      <button className={BTN_SECONDARY} onClick={() => showChanges(r)}>Zmiany</button>
                      <button className={BTN_SECONDARY} onClick={() => showServices(r)}>Usługi</button>
                      {can(session, "export") && (
                        <>
                          <button className={BTN_SECONDARY} onClick={() => exportRun(r, "json")}>JSON</button>
                          <button className={BTN_SECONDARY} onClick={() => exportRun(r, "csv")}>CSV</button>
                        </>
                      )}
                      {can(session, "integrations.export") && (
                        <button className={BTN_SECONDARY} onClick={() => sendToDefectDojo(r)}>DefectDojo</button>
                      )}
                    </>
                  )}
                </div>
              ),
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
              <ChangeTable changes={details.page.items} />
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
