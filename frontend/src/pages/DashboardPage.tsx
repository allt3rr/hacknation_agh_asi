import { useEffect } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { ChangeTable } from "../components/ChangeTable";
import { DataTable } from "../components/DataTable";
import { ScanProgress } from "../components/ScanProgress";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { Dashboard, Run, Session } from "../types";
import { BADGE, BTN_SECONDARY, STATUS_LABELS, formatDate, formatDuration } from "../utils";

const REFRESH_MS = 1000;
const HISTORY_RUNS = 10;

const CATEGORY_LABELS: Record<string, string> = {
  admin_panel: "panel admina",
  staging: "staging",
  interesting: "interesujące",
  iot: "IoT",
};

export function DashboardPage({ session }: { session: Session }) {
  const { data, error, reload } = useApiData(api.dashboard);
  const { data: runs, reload: reloadRuns } = useApiData(api.runs.list);
  const { run } = useNotice();
  const active = runs?.find((r) => r.status === "running");
  const scanRunning = (data?.scan_running ?? false) || active !== undefined;

  // Dopóki trwa skan, dashboard i pasek postępu odświeżają się same.
  useEffect(() => {
    if (!scanRunning) return;
    const timer = setInterval(() => {
      reload();
      reloadRuns();
    }, REFRESH_MS);
    return () => clearInterval(timer);
  }, [scanRunning, reload, reloadRuns]);

  if (error) {
    return (
      <p role="alert" className="my-3 text-red">
        {error}
      </p>
    );
  }
  if (!data) {
    return (
      <p role="status" className="my-3 text-muted">
        Ładowanie...
      </p>
    );
  }

  const refresh = () => {
    reload();
    reloadRuns();
  };
  const cancel = (r: Run) =>
    run(async () => {
      if (!confirm("Przerwać trwający skan? Wynik nie zostanie zapisany.")) return;
      await api.runs.cancel(r.id);
      refresh();
    });
  const finished = (runs ?? []).filter((r) => r.kind === "scan" && (r.status === "done" || r.status === "partial"));

  return (
    <>
      {active && <ScanProgress run={active} onCancel={can(session, "scans.run") ? () => cancel(active) : undefined} />}

      <KpiBar dashboard={data} onRefresh={refresh} />

      <div className="grid gap-3 xl:grid-cols-2">
        <Card title={`Najważniejsze znaleziska (${data.notable.length})`}>
          <DataTable
            label="Najważniejsze znaleziska"
            filterBy={(f) => [f.ip, f.name, f.category, f.title].join(" ")}
            columns={[
              { header: "Usługa", mono: true, render: (f) => `${f.ip}:${f.port}` },
              { header: "Znalezisko", render: (f) => f.name },
              { header: "Kategoria", title: (f) => f.category, render: (f) => <span className={BADGE}>{CATEGORY_LABELS[f.category] ?? f.category}</span> },
              { header: "Pewność", mono: true, render: (f) => `${f.confidence}%` },
              { header: "Tytuł", render: (f) => f.title ?? "" },
            ]}
            rows={data.notable}
            rowKey={(f) => `${f.ip}:${f.port}-${f.name}`}
            emptyText="Brak znalezisk"
          />
        </Card>

        <Card title={`Zmiany w ostatnim przebiegu (${data.recent_changes.length}/${data.changes_total})`}>
          <ChangeTable changes={data.recent_changes} label="Zmiany w ostatnim przebiegu" />
        </Card>
      </div>

      <div className="grid gap-3 xl:grid-cols-2">
        {finished.length > 1 && (
          <Card title="Historia przebiegów">
            <RunHistory runs={finished.slice(0, HISTORY_RUNS)} />
          </Card>
        )}
        <Card title="Technologie">
          <DataTable
            label="Technologie"
            columns={[
              { header: "Technologia", render: (t) => t.name },
              { header: "Kategoria", title: (t) => t.category, render: (t) => <span className={BADGE}>{t.category}</span> },
              { header: "Usługi", mono: true, render: (t) => t.services },
            ]}
            rows={data.technologies}
            rowKey={(t) => `${t.name}-${t.category}`}
          />
        </Card>
        {finished.length > 1 && (
          <Card title="Pora startu skanu">
            <TimeOfDay runs={finished} />
          </Card>
        )}
      </div>
    </>
  );
}

const TONES = { green: "text-green", orange: "text-orange", red: "text-red", muted: "text-muted", fg: "text-fg" } as const;

/** Zwarty pasek metryk: jeden wiersz `dl`, każda wartość ucinana w swojej kolumnie. */
function KpiBar({ dashboard: d, onRefresh }: { dashboard: Dashboard; onRefresh: () => void }) {
  const run = d.latest_run;
  const items: { term: string; value: string | number; tone?: keyof typeof TONES; title?: string }[] = [
    { term: "cele", value: d.targets },
    { term: "hosty aktywne", value: d.assets.active ?? 0, tone: "green" },
    { term: "niestabilne", value: d.assets.unstable ?? 0, tone: d.assets.unstable ? "orange" : "muted" },
    { term: "nieaktywne", value: d.assets.inactive ?? 0, tone: "muted" },
    { term: "usługi", value: d.services },
    { term: "zmiany", value: d.changes_total, tone: d.changes_total ? "orange" : "muted" },
    {
      term: "ostatni przebieg",
      value: run ? `${STATUS_LABELS[run.status] ?? run.status} · ${formatDate(run.started_at ?? run.created_at)}` : "brak",
      tone: run?.status === "failed" ? "red" : run?.status === "partial" ? "orange" : "fg",
      title: run ? `${STATUS_LABELS[run.status] ?? run.status}, ${formatDate(run.started_at ?? run.created_at)}, czas ${formatDuration(run.duration_ms)}` : undefined,
    },
    { term: "czas", value: run ? formatDuration(run.duration_ms) : "—" },
  ];
  return (
    <div className="panel mb-3 flex items-stretch">
      <dl className="grid min-w-0 flex-1 grid-cols-[repeat(auto-fit,minmax(7.5rem,1fr))]">
        {items.map((i) => (
          <div key={i.term} className="min-w-0 border-r border-b border-line px-3 py-1.5" title={i.title ?? `${i.term}: ${i.value}`}>
            <dt className="truncate text-[11px] tracking-wide text-muted uppercase">{i.term}</dt>
            <dd className={`mono truncate text-base font-semibold ${TONES[i.tone ?? "fg"]}`}>{i.value}</dd>
          </div>
        ))}
      </dl>
      <button className={`${BTN_SECONDARY} m-1.5 self-center`} onClick={onRefresh}>
        Odśwież
      </button>
    </div>
  );
}

/** Tabela z paskami: liczby są w tekście, pasek tylko ilustruje skalę (dostępne bez wzroku). */
function RunHistory({ runs }: { runs: Run[] }) {
  const maxHosts = Math.max(1, ...runs.map((r) => r.coverage.live_hosts ?? 0));
  return (
    <DataTable
      label="Kolejne skany"
      rows={runs}
      rowKey={(r) => r.id}
      columns={[
        { header: "Skan", mono: true, render: (r) => formatDate(r.started_at ?? r.created_at) },
        { header: "Status", render: (r) => STATUS_LABELS[r.status] ?? r.status },
        {
          header: "Hosty aktywne",
          render: (r) => (
            <div className="flex items-center gap-2">
              <span className="mono w-10 text-right">{r.coverage.live_hosts ?? 0}</span>
              <span aria-hidden="true" className="h-2 rounded-sm bg-accent" style={{ width: `${((r.coverage.live_hosts ?? 0) / maxHosts) * 160}px` }} />
            </div>
          ),
        },
        { header: "Usługi", render: (r) => r.coverage.services ?? "" },
        { header: "Czas trwania", render: (r) => formatDuration(r.duration_ms) },
      ]}
    />
  );
}

const DAY_PARTS: [string, number, number][] = [
  ["noc (0-6)", 0, 6],
  ["rano (6-12)", 6, 12],
  ["dzień (12-18)", 12, 18],
  ["wieczór (18-24)", 18, 24],
];

/** Średnia liczba hostów i usług dla skanów rozpoczętych o danej porze (czas lokalny przeglądarki). */
function TimeOfDay({ runs }: { runs: Run[] }) {
  const average = (items: number[]) => (items.length ? Math.round(items.reduce((a, b) => a + b, 0) / items.length) : null);
  const rows = DAY_PARTS.map(([label, from, to]) => {
    const inPart = runs.filter((r) => {
      const hour = new Date(r.started_at ?? r.created_at).getHours();
      return hour >= from && hour < to;
    });
    return {
      label,
      count: inPart.length,
      hosts: average(inPart.flatMap((r) => (r.coverage.live_hosts === undefined ? [] : [r.coverage.live_hosts]))),
      services: average(inPart.flatMap((r) => (r.coverage.services === undefined ? [] : [r.coverage.services]))),
    };
  });
  return (
    <DataTable
      label="Średnie wyniki wg pory startu skanu"
      rows={rows}
      rowKey={(r) => r.label}
      columns={[
        { header: "Pora startu", render: (r) => r.label },
        { header: "Skany", render: (r) => r.count },
        { header: "Śr. hosty aktywne", render: (r) => r.hosts ?? "—" },
        { header: "Śr. usługi", render: (r) => r.services ?? "—" },
      ]}
    />
  );
}
