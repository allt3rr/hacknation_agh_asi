import { useEffect, useState } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { ScanProgress } from "../components/ScanProgress";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { Dashboard, Run, ScheduleEntry, Session } from "../types";
import { BADGE, BTN_SECONDARY, STATUS_LABELS, formatDate, formatDuration, formatWindows, nextScheduledStart } from "../utils";

const REFRESH_MS = 1000;
const HISTORY_RUNS = 10;
// shortcut: „od początku” w porze startu obejmuje maks. 500 ostatnich przebiegów (limit API); przy większej historii agregować w backendzie.
const RUNS_LIMIT = 500;
const loadRuns = () => api.runs.list(RUNS_LIMIT);

const CATEGORY_LABELS: Record<string, string> = {
  admin_panel: "panel admina",
  staging: "staging",
  interesting: "interesujące",
  iot: "IoT",
};

export function DashboardPage({ session }: { session: Session }) {
  const { data, error, reload } = useApiData(api.dashboard);
  const { data: runs, reload: reloadRuns } = useApiData(loadRuns);
  const { data: schedules, reload: reloadSchedule } = useApiData(api.schedules.list);
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
    reloadSchedule();
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

      <div className="grid gap-x-3 xl:grid-cols-2">
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

        <Card title="Zaplanowane przebiegi">
          {schedules ? <ScheduleSummary schedules={schedules} /> : <p className="text-muted">Ładowanie...</p>}
        </Card>

        <Card title="Historia przebiegów">
          <RunHistory runs={finished.slice(0, HISTORY_RUNS)} />
        </Card>

        <TimeOfDayCard runs={finished} />
      </div>
    </>
  );
}

const TONES = { green: "text-green", orange: "text-orange", red: "text-red", muted: "text-muted", fg: "text-fg" } as const;

/** Udział niestabilnych; niezerowy udział poniżej 1% to „<1%”, nie mylące „0%”. */
function unstablePercent(unstable: number, hosts: number): string {
  if (!hosts) return "—";
  const pct = (unstable / hosts) * 100;
  return unstable > 0 && pct < 1 ? "<1%" : `${Math.round(pct)}%`;
}

/** Zwarty pasek metryk: jeden wiersz `dl`, każda wartość ucinana w swojej kolumnie. */
function KpiBar({ dashboard: d, onRefresh }: { dashboard: Dashboard; onRefresh: () => void }) {
  const active = d.assets.active ?? 0;
  const unstable = d.assets.unstable ?? 0;
  const hosts = active + unstable + (d.assets.inactive ?? 0);
  const items: { term: string; value: string | number; tone?: keyof typeof TONES }[] = [
    { term: "hosty aktywne", value: active, tone: "green" },
    { term: "hosty niestabilne", value: unstable, tone: unstable ? "orange" : "muted" },
    { term: "% niestabilnych", value: unstablePercent(unstable, hosts), tone: unstable ? "orange" : "muted" },
    { term: "usługi", value: d.services },
    { term: "skany", value: d.scans_total },
  ];
  return (
    <div className="panel mb-3 flex items-stretch">
      <dl className="grid min-w-0 flex-1 grid-cols-[repeat(auto-fit,minmax(7.5rem,1fr))]">
        {items.map((i) => (
          <div key={i.term} className="min-w-0 border-r border-b border-line px-3 py-1.5" title={`${i.term}: ${i.value}`}>
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

/** Pozycje harmonogramu tylko do odczytu; edycja w Skany → Harmonogram. */
function ScheduleSummary({ schedules }: { schedules: ScheduleEntry[] }) {
  return (
    <DataTable
      label="Pozycje harmonogramu"
      rows={schedules}
      rowKey={(s) => s.id}
      emptyText="brak pozycji harmonogramu"
      columns={[
        { header: "Pozycja", render: (s) => s.name },
        { header: "Cele", mono: true, render: (s) => s.target_ids.length - s.missing_targets },
        { header: "Częstotliwość", render: (s) => `co ${s.every_hours} h` },
        { header: "Okna (UTC)", title: (s) => formatWindows(s.windows), render: (s) => formatWindows(s.windows) },
        {
          header: "Następny start (najwcześniej)",
          render: (s) => <span className={s.enabled ? "mono" : "text-muted"}>{nextScheduledStart(s)}</span>,
        },
      ]}
    />
  );
}

/** Liczba podatności z progami koloru; „—”, gdy sprawdzenie nie zostało zakończone. */
function VulnCount({ run: r }: { run: Run }) {
  if (r.vuln_state !== "done") return <span className="text-muted">—</span>;
  const n = r.vuln_summary.vulnerabilities ?? 0;
  return <span className={`mono font-semibold ${n === 0 ? "text-green" : n <= 2 ? "text-orange" : "text-red"}`}>{n}</span>;
}

function RunHistory({ runs }: { runs: Run[] }) {
  return (
    <DataTable
      label="Kolejne skany"
      rows={runs}
      rowKey={(r) => r.id}
      emptyText="Brak zakończonych skanów"
      columns={[
        { header: "Skan", mono: true, render: (r) => formatDate(r.started_at ?? r.created_at) },
        { header: "Status", render: (r) => STATUS_LABELS[r.status] ?? r.status },
        { header: "Hosty aktywne", mono: true, render: (r) => r.coverage.live_hosts ?? 0 },
        { header: "Usługi", render: (r) => r.coverage.services ?? "" },
        { header: "Podatności", render: (r) => <VulnCount run={r} /> },
        { header: "Czas trwania", render: (r) => formatDuration(r.duration_ms) },
      ]}
    />
  );
}

const RANGES: [string, number | null][] = [
  ["7 dni", 7],
  ["31 dni", 31],
  ["365 dni", 365],
  ["od początku", null],
];

function TimeOfDayCard({ runs }: { runs: Run[] }) {
  const [days, setDays] = useState<number | null>(null);
  const since = days === null ? -Infinity : Date.now() - days * 86_400_000;
  const inRange = runs.filter((r) => new Date(r.started_at ?? r.created_at).getTime() >= since);
  return (
    <Card
      title="Czas działania skanów"
      actions={
        <div role="group" aria-label="Zakres" className="flex flex-wrap gap-1">
          {RANGES.map(([label, value]) => (
            <button
              key={label}
              type="button"
              aria-pressed={days === value}
              className={days === value ? "border border-accent" : BTN_SECONDARY}
              onClick={() => setDays(value)}
            >
              {label}
            </button>
          ))}
        </div>
      }
    >
      <TimeOfDay runs={inRange} />
    </Card>
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
