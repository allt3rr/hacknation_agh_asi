import { useEffect } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { ChangeTable } from "../components/ChangeTable";
import { DataTable } from "../components/DataTable";
import { StatCard } from "../components/StatCard";
import { useApiData } from "../hooks";
import type { Dashboard, NotableFinding, Run } from "../types";
import { BTN_SECONDARY, STATUS_LABELS, formatDate, formatDuration, parseRunStats } from "../utils";

const REFRESH_MS = 5000;
const HISTORY_RUNS = 10;
const BADGE = "mr-1 my-px inline-block rounded-full border border-line bg-bg px-2 py-px text-xs";

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

  return (
    <>
      <Card
        title="Podsumowanie"
        actions={
          <button className={BTN_SECONDARY} onClick={refresh}>
            Odśwież
          </button>
        }
      >
        <Stats dashboard={data} />
      </Card>

      <Card title="Najważniejsze znaleziska">
        <p className="mb-2 text-muted">Panele administracyjne, środowiska testowe, urządzenia IoT i inne interesujące usługi z ostatniego skanu.</p>
        <NotableFindings findings={data.interesting} />
      </Card>

      <Card title="Zmiany w ostatnim skanie">
        <ChangeTable changes={data.changes} label="Zmiany w ostatnim skanie" />
      </Card>

      {runs && runs.length > 1 && (
        <Card title="Zmiany w czasie">
          <RunHistory runs={runs.slice(0, HISTORY_RUNS)} />
        </Card>
      )}

      {runs && runs.length > 1 && (
        <Card title="Różnice zależne od pory dnia">
          <p className="mb-2 text-muted">Średnie z ostatnich skanów według godziny startu. Duże różnice wskazują hosty widoczne tylko w części doby.</p>
          <TimeOfDay runs={runs} />
        </Card>
      )}

      <Card title="Technologie">
        <DataTable
          label="Technologie"
          columns={[
            { header: "Technologia", render: ([name]) => name },
            { header: "Liczba usług", render: ([, count]) => count },
          ]}
          rows={data.technologies}
          rowKey={([name]) => name}
        />
      </Card>
    </>
  );
}

function Stats({ dashboard }: { dashboard: Dashboard }) {
  const { counts, latest_run: run } = dashboard;
  // Lista zmian z API jest ucięta (200), pełna liczba jest w statystykach przebiegu.
  const changes = (run && parseRunStats(run.stats_json).changes) ?? dashboard.changes.length;
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(130px,1fr))] gap-3">
      <StatCard label="Cele" value={counts.targets} />
      <StatCard label="Hosty aktywne" value={counts.hosts.active ?? 0} />
      <StatCard label="Hosty niestabilne" value={counts.hosts.unstable ?? 0} />
      <StatCard label="Hosty nieaktywne" value={counts.hosts.inactive ?? 0} />
      <StatCard label="Usługi" value={dashboard.services} />
      <StatCard label="Zmiany" value={changes} />
      <StatCard
        label="Ostatni skan"
        value={run ? STATUS_LABELS[run.status] : "brak"}
        hint={run ? `${formatDate(run.started_at)}, czas: ${formatDuration(run.duration_secs)}` : undefined}
      />
      <StatCard label="Skan w toku" value={dashboard.scan_running ? "tak" : "nie"} />
    </div>
  );
}

function NotableFindings({ findings }: { findings: NotableFinding[] }) {
  return (
    <DataTable
      label="Najważniejsze znaleziska"
      filterBy={(f) => [f.key, f.name, f.category, f.title].join(" ")}
      columns={[
        { header: "Usługa", render: (f) => f.key },
        { header: "Znalezisko", render: (f) => f.name },
        { header: "Kategoria", render: (f) => <span className={BADGE}>{CATEGORY_LABELS[f.category] ?? f.category}</span> },
        { header: "Pewność", render: (f) => `${f.confidence}%` },
        { header: "Tytuł strony", render: (f) => f.title ?? "" },
      ]}
      rows={findings}
      rowKey={(f) => `${f.key}-${f.name}`}
      emptyText="Brak znalezisk"
    />
  );
}

/** Tabela z paskami: liczby są w tekście, pasek tylko ilustruje skalę (dostępne bez wzroku). */
function RunHistory({ runs }: { runs: Run[] }) {
  const rows = runs.map((run) => ({ run, stats: parseRunStats(run.stats_json) }));
  const maxChanges = Math.max(1, ...rows.map((r) => r.stats.changes ?? 0));
  return (
    <DataTable
      label="Zmiany w kolejnych skanach"
      rows={rows}
      rowKey={(r) => r.run.id}
      columns={[
        { header: "Skan", render: (r) => formatDate(r.run.started_at) },
        { header: "Status", render: (r) => STATUS_LABELS[r.run.status] },
        { header: "Hosty", render: (r) => r.stats.live_hosts ?? "" },
        { header: "Usługi", render: (r) => r.stats.services ?? "" },
        {
          header: "Zmiany",
          render: (r) => (
            <div className="flex items-center gap-2">
              <span className="w-10 text-right tabular-nums">{r.stats.changes ?? 0}</span>
              <span aria-hidden="true" className="h-2.5 rounded-sm bg-accent" style={{ width: `${((r.stats.changes ?? 0) / maxChanges) * 160}px` }} />
            </div>
          ),
        },
        { header: "Czas trwania", render: (r) => formatDuration(r.run.duration_secs) },
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

/** Średnia liczba hostów, usług i zmian dla skanów rozpoczętych o danej porze (czas lokalny przeglądarki). */
function TimeOfDay({ runs }: { runs: Run[] }) {
  const finished = runs.filter((r) => r.status === "completed" || r.status === "partial");
  const average = (items: number[]) => (items.length ? Math.round(items.reduce((a, b) => a + b, 0) / items.length) : null);
  const rows = DAY_PARTS.map(([label, from, to]) => {
    const inPart = finished.filter((r) => {
      const hour = new Date(r.started_at).getHours();
      return hour >= from && hour < to;
    });
    const stats = inPart.map((r) => parseRunStats(r.stats_json));
    return {
      label,
      count: inPart.length,
      hosts: average(stats.flatMap((s) => (s.live_hosts === undefined ? [] : [s.live_hosts]))),
      services: average(stats.flatMap((s) => (s.services === undefined ? [] : [s.services]))),
      changes: average(stats.flatMap((s) => (s.changes === undefined ? [] : [s.changes]))),
    };
  });
  const show = (value: number | null) => value ?? "—";
  return (
    <DataTable
      label="Różnice zależne od pory dnia"
      rows={rows}
      rowKey={(r) => r.label}
      columns={[
        { header: "Pora startu", render: (r) => r.label },
        { header: "Skany", render: (r) => r.count },
        { header: "Śr. hosty aktywne", render: (r) => show(r.hosts) },
        { header: "Śr. usługi", render: (r) => show(r.services) },
        { header: "Śr. zmiany", render: (r) => show(r.changes) },
      ]}
    />
  );
}
