import { api } from "../api";
import { Card } from "../components/Card";
import { ChangeTable } from "../components/ChangeTable";
import { DataTable } from "../components/DataTable";
import { StatCard } from "../components/StatCard";
import { useApiData } from "../hooks";
import type { Dashboard, NotableFinding } from "../types";
import { BTN_SECONDARY, formatDate } from "../utils";

export function DashboardPage() {
  const { data, error, reload } = useApiData(api.dashboard);

  if (error) {
    return <p className="my-3.5 text-red">{error}</p>;
  }
  if (!data) {
    return <p className="my-3.5 text-muted">Ładowanie...</p>;
  }

  return (
    <>
      <Card actions={<button className={BTN_SECONDARY} onClick={reload}>Odśwież</button>}>
        <Stats dashboard={data} />
      </Card>

      <Card title="Najważniejsze znaleziska">
        <NotableFindings findings={data.interesting} />
      </Card>

      <Card title="Zmiany w ostatnim skanie">
        <ChangeTable changes={data.changes} />
      </Card>

      <Card title="Technologie">
        <DataTable
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
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(150px,1fr))] gap-3">
      <StatCard label="Cele" value={counts.targets} />
      <StatCard label="Hosty aktywne" value={counts.hosts.active ?? 0} />
      <StatCard label="Hosty niestabilne" value={counts.hosts.unstable ?? 0} />
      <StatCard label="Hosty nieaktywne" value={counts.hosts.inactive ?? 0} />
      <StatCard label="Usługi" value={dashboard.services} />
      <StatCard label="Zmiany" value={dashboard.changes.length} />
      <StatCard
        label="Ostatni skan"
        value={run ? run.status : "brak"}
        hint={run ? formatDate(run.started_at) : undefined}
      />
      <StatCard label="Skan w toku" value={dashboard.scan_running ? "tak" : "nie"} />
    </div>
  );
}

function NotableFindings({ findings }: { findings: NotableFinding[] }) {
  return (
    <DataTable
      columns={[
        { header: "Usługa", render: (f) => f.key },
        { header: "Znalezisko", render: (f) => f.name },
        { header: "Kategoria", render: (f) => <span className="mr-1 my-px inline-block rounded-full border border-line bg-bg px-2 py-px text-xs">{f.category}</span> },
        { header: "Pewność", render: (f) => `${f.confidence}%` },
        { header: "Tytuł strony", render: (f) => f.title ?? "" },
      ]}
      rows={findings}
      rowKey={(f) => `${f.key}-${f.name}`}
      emptyText="Brak znalezisk"
    />
  );
}
