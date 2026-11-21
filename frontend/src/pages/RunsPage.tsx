import { useState, type ReactNode } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { ChangeTable } from "../components/ChangeTable";
import { DataTable } from "../components/DataTable";
import { FilePicker } from "../components/FilePicker";
import { NoticeBar } from "../components/NoticeBar";
import { ObservationTable } from "../components/ObservationTable";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { Role, Run } from "../types";
import { downloadBlob, fileFormat, formatDate, parseRunStats } from "../utils";

interface Details {
  title: string;
  content: ReactNode;
}

export function RunsPage({ role }: { role: Role }) {
  const { data: runs, error, reload } = useApiData(api.runs.list);
  const { notice, info, run } = useNotice();
  const [maxMinutes, setMaxMinutes] = useState("");
  const [details, setDetails] = useState<Details | null>(null);

  const startScan = () =>
    run(async () => {
      await api.runs.start(maxMinutes ? Number(maxMinutes) : undefined);
      info("Skan uruchomiony. Odśwież listę, aby zobaczyć postęp.");
      await reload();
    });

  const importResults = (file: File) =>
    run(async () => {
      await api.runs.importResults(fileFormat(file.name), await file.text());
      info("Wyniki zaimportowane");
      await reload();
    });

  const showChanges = (r: Run) =>
    run(async () => {
      const changes = await api.runs.changes(r.id);
      setDetails({ title: `Zmiany: ${formatDate(r.started_at)}`, content: <ChangeTable changes={changes} /> });
    });

  const showServices = (r: Run) =>
    run(async () => {
      const observations = await api.runs.observations(r.id);
      setDetails({
        title: `Usługi: ${formatDate(r.started_at)}`,
        content: <ObservationTable observations={observations} />,
      });
    });

  const exportRun = (r: Run, format: "csv" | "json") =>
    run(async () => downloadBlob(await api.runs.exportFile(r.id, format), `asi-${r.id}.${format}`));

  const sendToDefectDojo = (r: Run) =>
    run(async () => {
      await api.runs.sendToDefectDojo(r.id);
      info("Wysłano do DefectDojo");
    });

  return (
    <>
      <NoticeBar notice={notice} />

      {can(role, "scan") && (
        <Card title="Nowy skan">
          <div className="row">
            <button onClick={startScan}>Uruchom skan</button>
            <label className="muted">
              limit czasu (min){" "}
              <input
                type="number"
                min={1}
                className="narrow"
                value={maxMinutes}
                onChange={(e) => setMaxMinutes(e.target.value)}
              />
            </label>
          </div>
          <div className="row">
            <span className="muted">Import wyników skanu (JSON/CSV):</span>
            <FilePicker accept=".csv,.json" buttonLabel="Importuj" onSubmit={importResults} />
          </div>
        </Card>
      )}

      <Card title="Przebiegi" actions={<button className="secondary" onClick={reload}>Odśwież</button>}>
        {error && <p className="notice error">{error}</p>}
        <DataTable
          rows={runs ?? []}
          rowKey={(r) => r.id}
          columns={[
            { header: "Start", render: (r) => formatDate(r.started_at) },
            { header: "Źródło", render: (r) => r.source },
            { header: "Status", render: (r) => <span className={`status status-${r.status}`}>{r.status}</span> },
            { header: "Czas [s]", render: (r) => r.duration_secs?.toFixed(1) ?? "" },
            { header: "Statystyki", render: (r) => <RunStatsSummary run={r} /> },
            {
              header: "",
              render: (r) => (
                <div className="actions">
                  <button className="secondary" onClick={() => showChanges(r)}>Zmiany</button>
                  <button className="secondary" onClick={() => showServices(r)}>Usługi</button>
                  <button className="secondary" onClick={() => exportRun(r, "json")}>JSON</button>
                  <button className="secondary" onClick={() => exportRun(r, "csv")}>CSV</button>
                  {can(role, "create") && (
                    <button className="secondary" onClick={() => sendToDefectDojo(r)}>DefectDojo</button>
                  )}
                </div>
              ),
            },
          ]}
        />
      </Card>

      {details && (
        <Card title={details.title} actions={<button className="secondary" onClick={() => setDetails(null)}>Zamknij</button>}>
          {details.content}
        </Card>
      )}
    </>
  );
}

function RunStatsSummary({ run }: { run: Run }) {
  const stats = parseRunStats(run.stats_json);
  const parts = [
    stats.live_hosts !== undefined && `hosty: ${stats.live_hosts}`,
    stats.services !== undefined && `usługi: ${stats.services}`,
    stats.changes !== undefined && `zmiany: ${stats.changes}`,
    stats.pending ? `zaległe: ${stats.pending}` : null,
    stats.failed ? `błędy: ${stats.failed}` : null,
  ].filter(Boolean);
  return <span className="muted">{parts.join(", ")}</span>;
}
