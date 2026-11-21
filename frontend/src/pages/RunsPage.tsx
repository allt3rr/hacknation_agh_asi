import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { ChangeTable } from "../components/ChangeTable";
import { DataTable } from "../components/DataTable";
import { EditableText } from "../components/EditableText";
import { FilePicker } from "../components/FilePicker";
import { ObservationTable } from "../components/ObservationTable";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { Annotation, Change, Observation, Role, Run, RunStatus } from "../types";
import { BTN_SECONDARY, STATUS_LABELS, downloadBlob, fileFormat, formatDate, formatDuration, parseRunStats } from "../utils";

const STATUS_COLORS: Record<RunStatus, string> = {
  running: "text-accent",
  completed: "text-green",
  partial: "text-orange",
  aborted: "",
  failed: "text-red",
};

const REFRESH_MS = 5000;

// Dane trzymamy w stanie, a tabelę renderujemy na bieżąco, żeby po zapisie adnotacji widok się odświeżył.
interface Details {
  title: string;
  changes?: Change[];
  observations?: Observation[];
  runId?: string;
}

const runLabel = (r: Run) => `${formatDate(r.started_at)} (${STATUS_LABELS[r.status]})`;

export function RunsPage({ role }: { role: Role }) {
  const { data: runs, error, reload } = useApiData(api.runs.list);
  const { data: annotationList, reload: reloadAnnotations } = useApiData(api.annotations.list);
  const { info, run } = useNotice();
  const [maxMinutes, setMaxMinutes] = useState("");
  const [details, setDetails] = useState<Details | null>(null);
  const [compareFrom, setCompareFrom] = useState("");
  const [compareTo, setCompareTo] = useState("");
  const detailsHeading = useRef<HTMLHeadingElement>(null);

  const annotations = useMemo(() => new Map((annotationList ?? []).map((a) => [a.key, a])), [annotationList]);
  const scanRunning = runs?.some((r) => r.status === "running") ?? false;

  // Lista odświeża się sama, dopóki trwa skan.
  useEffect(() => {
    if (!scanRunning) return;
    const timer = setInterval(reload, REFRESH_MS);
    return () => clearInterval(timer);
  }, [scanRunning, reload]);

  useEffect(() => {
    if (!details) return;
    detailsHeading.current?.focus();
    detailsHeading.current?.scrollIntoView({ block: "start" });
  }, [details]);

  // Domyślnie porównujemy dwa ostatnie przebiegi (lista jest posortowana od najnowszego).
  const from = compareFrom || runs?.[1]?.id || "";
  const to = compareTo || runs?.[0]?.id || "";

  const startScan = () =>
    run(async () => {
      await api.runs.start(maxMinutes ? Number(maxMinutes) : undefined);
      info("Skan uruchomiony. Lista przebiegów odświeża się automatycznie.");
      await reload();
    });

  const importResults = (file: File) =>
    run(async () => {
      await api.runs.importResults(fileFormat(file.name), await file.text());
      info(`Zaimportowano wyniki z pliku ${file.name}`);
      await reload();
    });

  // Błędy obsługuje formularz adnotacji (komunikat przy formularzu, nie na górze strony).
  const saveAnnotation = async (annotation: Annotation) => {
    await api.annotations.save(annotation);
    await reloadAnnotations();
  };

  const showChanges = (r: Run) =>
    run(async () => {
      const changes = await api.runs.changes(r.id);
      setDetails({ title: `Zmiany w skanie ${formatDate(r.started_at)}`, changes });
    });

  const showServices = (r: Run) =>
    run(async () => {
      const observations = await api.runs.observations(r.id);
      setDetails({ title: `Usługi w skanie ${formatDate(r.started_at)}`, observations, runId: r.id });
    });

  const compare = () =>
    run(async () => {
      const changes = await api.runs.compare(from, to);
      const name = (id: string) => formatDate(runs?.find((r) => r.id === id)?.started_at ?? id);
      setDetails({ title: `Porównanie: ${name(from)} → ${name(to)}`, changes });
    });

  const exportRun = (r: Run, format: "csv" | "json") =>
    run(async () => downloadBlob(await api.runs.exportFile(r.id, format), `asi-${r.id}.${format}`));

  const sendToDefectDojo = (r: Run) =>
    run(async () => {
      await api.runs.sendToDefectDojo(r.id);
      info(`Wysłano skan ${formatDate(r.started_at)} do DefectDojo`);
    });

  const sendSelected = (runId: string) => (keys: string[]) =>
    run(async () => {
      await api.runs.sendToDefectDojo(runId, keys);
      info(`Wysłano ${keys.length} wybranych usług do DefectDojo`);
    });

  const saveNote = (r: Run, note: string) =>
    run(async () => {
      await api.runs.updateNote(r.id, note);
      info(`Zapisano notatkę skanu ${formatDate(r.started_at)}`);
      await reload();
    });

  return (
    <>

      {can(role, "scan") && (
        <Card title="Nowy skan">
          <div className="my-2 flex flex-wrap items-center gap-2">
            <button onClick={startScan} disabled={scanRunning}>
              {scanRunning ? "Skan w toku..." : "Uruchom skan"}
            </button>
            <label htmlFor="max-minutes" className="text-muted">
              Limit czasu (min)
            </label>
            <input
              id="max-minutes"
              type="number"
              min={1}
              className="w-20"
              value={maxMinutes}
              aria-describedby="max-minutes-hint"
              onChange={(e) => setMaxMinutes(e.target.value)}
            />
            <span id="max-minutes-hint" className="text-muted">
              Po przekroczeniu skan kończy się jako częściowy. Okna czasowe i częstotliwość ustawia się w config/asi.toml.
            </span>
          </div>
          <div className="my-2 flex flex-wrap items-center gap-2">
            <span className="text-muted">Import wyników skanu (JSON/CSV):</span>
            <FilePicker accept=".csv,.json" label="Plik z wynikami skanu" buttonLabel="Importuj" onSubmit={importResults} />
          </div>
        </Card>
      )}

      <Card title="Przebiegi" actions={<button className={BTN_SECONDARY} onClick={reload}>Odśwież</button>}>
        {error && (
          <p role="alert" className="my-3.5 text-red">
            {error}
          </p>
        )}
        {(runs?.length ?? 0) >= 2 && (
          <div className="my-2 flex flex-wrap items-center gap-2">
            <label htmlFor="compare-from">Porównaj skan</label>
            <select id="compare-from" value={from} onChange={(e) => setCompareFrom(e.target.value)}>
              {runs?.map((r) => (
                <option key={r.id} value={r.id}>
                  {runLabel(r)}
                </option>
              ))}
            </select>
            <label htmlFor="compare-to">z</label>
            <select id="compare-to" value={to} onChange={(e) => setCompareTo(e.target.value)}>
              {runs?.map((r) => (
                <option key={r.id} value={r.id}>
                  {runLabel(r)}
                </option>
              ))}
            </select>
            <button className={BTN_SECONDARY} onClick={compare} disabled={from === to}>
              Porównaj
            </button>
          </div>
        )}
        <DataTable
          rows={runs ?? []}
          rowKey={(r) => r.id}
          label="Przebiegi skanów"
          emptyText={runs ? "Brak przebiegów" : "Ładowanie..."}
          columns={[
            { header: "Start", render: (r) => formatDate(r.started_at) },
            { header: "Źródło", render: (r) => r.source },
            { header: "Status", render: (r) => <span className={`font-medium ${STATUS_COLORS[r.status]}`}>{STATUS_LABELS[r.status]}</span> },
            { header: "Czas trwania", render: (r) => formatDuration(r.duration_secs) },
            { header: "Statystyki", render: (r) => <RunStatsSummary run={r} /> },
            {
              header: "Notatka",
              render: (r) =>
                can(role, "modify") ? (
                  <EditableText key={r.note ?? ""} label={`Notatka skanu ${formatDate(r.started_at)}`} value={r.note ?? ""} onSave={(note) => saveNote(r, note)} />
                ) : (
                  r.note
                ),
            },
            {
              header: "",
              render: (r) => {
                const name = formatDate(r.started_at);
                return (
                  <div className="flex flex-wrap gap-1">
                    <button className={BTN_SECONDARY} aria-label={`Zmiany w skanie ${name}`} onClick={() => showChanges(r)}>Zmiany</button>
                    <button className={BTN_SECONDARY} aria-label={`Usługi w skanie ${name}`} onClick={() => showServices(r)}>Usługi</button>
                    <button className={BTN_SECONDARY} aria-label={`Eksport skanu ${name} do JSON`} onClick={() => exportRun(r, "json")}>JSON</button>
                    <button className={BTN_SECONDARY} aria-label={`Eksport skanu ${name} do CSV`} onClick={() => exportRun(r, "csv")}>CSV</button>
                    {can(role, "create") && (
                      <button className={BTN_SECONDARY} aria-label={`Wyślij skan ${name} do DefectDojo`} onClick={() => sendToDefectDojo(r)}>DefectDojo</button>
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
          title={details.title}
          headingRef={detailsHeading}
          actions={<button className={BTN_SECONDARY} onClick={() => setDetails(null)}>Zamknij</button>}
        >
          {details.changes && <ChangeTable changes={details.changes} label={details.title} />}
          {details.observations && (
            <ObservationTable
              observations={details.observations}
              annotations={annotations}
              onSaveAnnotation={can(role, "modify") ? saveAnnotation : undefined}
              onSendToDefectDojo={can(role, "create") && details.runId ? sendSelected(details.runId) : undefined}
            />
          )}
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
    stats.error ?? null,
  ].filter(Boolean);
  return <span className="text-muted">{parts.join(", ")}</span>;
}
