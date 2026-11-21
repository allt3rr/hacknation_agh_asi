import { useEffect } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { ChangeTable } from "../components/ChangeTable";
import { DataTable } from "../components/DataTable";
import { StatCard } from "../components/StatCard";
import { useApiData } from "../hooks";
import type { Dashboard, Run } from "../types";
import { BADGE, BTN_SECONDARY, STATUS_LABELS, formatDate, formatDuration } from "../utils";

const REFRESH_MS = 5000;
const HISTORY_RUNS = 10;

const CATEGORY_LABELS: Record<string, string> = {
  admin_panel: "panel administracyjny",
  staging: "środowisko testowe / staging",
  interesting: "interesujące",
  iot: "urządzenie IoT",
};

export function DashboardPage() {
  const { data, error, reload } = useApiData(api.dashboard);
  const { data: runs, reload: reloadRuns } = useApiData(api.runs.list);
  const scanRunning = data?.scan_running ?? false;

  // Dopóki trwa skan, dashboard odświeża się sam.
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
      <p role="alert" className="my-3.5 text-red">
        {error}
      </p>
    );
  }
  if (!data) {
    return (
      <p role="status" className="my-3.5 text-muted">
        Ładowanie...
      </p>
    );
  }

  const refresh = () => {
    reload();
    reloadRuns();
  };
  const finished = (runs ?? []).filter((r) => r.kind === "scan" && (r.status === "done" || r.status === "partial"));

  return (
    <>
      <Card title="Podsumowanie" actions={<button className={BTN_SECONDARY} onClick={refresh}>Odśwież</button>}>
        <Stats dashboard={data} />
      </Card>

      <Card title="Najważniejsze znaleziska">
        <p className="mb-2 text-muted">Panele administracyjne, środowiska testowe, urządzenia IoT i inne interesujące usługi z ostatniego przebiegu.</p>
        <DataTable
          label="Najważniejsze znaleziska"
          filterBy={(f) => [f.ip, f.name, f.category, f.title].join(" ")}
          columns={[
            { header: "Usługa", render: (f) => `${f.ip}:${f.port}` },
            { header: "Znalezisko", render: (f) => f.name },
            { header: "Kategoria", render: (f) => <span className={BADGE}>{CATEGORY_LABELS[f.category] ?? f.category}</span> },
            { header: "Pewność", render: (f) => `${f.confidence}%` },
            { header: "Tytuł strony", render: (f) => f.title ?? "" },
          ]}
          rows={data.notable}
          rowKey={(f) => `${f.ip}:${f.port}-${f.name}`}
          emptyText="Brak znalezisk"
        />
      </Card>

      <Card title={`Zmiany w ostatnim przebiegu (${data.changes_total})`}>
        <ChangeTable changes={data.recent_changes} label="Zmiany w ostatnim przebiegu" />
        {data.changes_total > data.recent_changes.length && (
          <p className="my-2 text-muted">Pokazano {data.recent_changes.length} z {data.changes_total}. Wszystkie: zakładka Skany → Zmiany.</p>
        )}
      </Card>

      {finished.length > 1 && (
        <>
          <Card title="Zmiany w czasie">
            <RunHistory runs={finished.slice(0, HISTORY_RUNS)} />
          </Card>
          <Card title="Różnice zależne od pory dnia">
            <p className="mb-2 text-muted">Średnie ze skanów według godziny startu. Duże różnice wskazują hosty widoczne tylko w części doby.</p>
            <TimeOfDay runs={finished} />
          </Card>
        </>
      )}

      <Card title="Technologie">
        <DataTable
          label="Technologie"
          columns={[
            { header: "Technologia", render: (t) => t.name },
            { header: "Kategoria", render: (t) => <span className={BADGE}>{t.category}</span> },
            { header: "Liczba usług", render: (t) => t.services },
          ]}
          rows={data.technologies}
          rowKey={(t) => `${t.name}-${t.category}`}
        />
      </Card>
    </>
  );
}

function Stats({ dashboard: d }: { dashboard: Dashboard }) {
  const run = d.latest_run;
  const when = run ? formatDate(run.started_at ?? run.created_at) : "";
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(130px,1fr))] gap-3">
      <StatCard label="Cele" value={d.targets} />
      <StatCard label="Hosty aktywne" value={d.assets.active ?? 0} />
      <StatCard label="Hosty niestabilne" value={d.assets.unstable ?? 0} />
      <StatCard label="Hosty nieaktywne" value={d.assets.inactive ?? 0} />
      <StatCard label="Usługi" value={d.services} />
      <StatCard label="Zmiany" value={d.changes_total} />
      <StatCard
        label="Ostatni przebieg"
        value={run ? STATUS_LABELS[run.status] ?? run.status : "brak"}
        hint={run ? (run.duration_ms != null ? `${when}, czas: ${formatDuration(run.duration_ms)}` : when) : undefined}
      />
      <StatCard label="Skan w toku" value={d.scan_running ? "tak" : "nie"} />
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
        { header: "Skan", render: (r) => formatDate(r.started_at ?? r.created_at) },
        { header: "Status", render: (r) => STATUS_LABELS[r.status] ?? r.status },
        {
          header: "Hosty aktywne",
          render: (r) => (
            <div className="flex items-center gap-2">
              <span className="w-10 text-right tabular-nums">{r.coverage.live_hosts ?? 0}</span>
              <span aria-hidden="true" className="h-2.5 rounded-sm bg-accent" style={{ width: `${((r.coverage.live_hosts ?? 0) / maxHosts) * 160}px` }} />
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
      label="Różnice zależne od pory dnia"
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
