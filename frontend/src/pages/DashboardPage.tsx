import { api } from "../api";
import { Card } from "../components/Card";
import { ChangeTable } from "../components/ChangeTable";
import { DataTable } from "../components/DataTable";
import { StatCard } from "../components/StatCard";
import { useApiData } from "../hooks";
import type { Dashboard } from "../types";
import { BADGE, BTN_SECONDARY, formatDate } from "../utils";

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
        <DataTable
          columns={[
            { header: "Usługa", render: (f) => `${f.ip}:${f.port}` },
            { header: "Znalezisko", render: (f) => f.name },
            { header: "Kategoria", render: (f) => <span className={BADGE}>{f.category}</span> },
            { header: "Pewność", render: (f) => `${f.confidence}%` },
            { header: "Tytuł strony", render: (f) => f.title ?? "" },
          ]}
          rows={data.notable}
          rowKey={(f) => `${f.ip}:${f.port}-${f.name}`}
          emptyText="Brak znalezisk"
        />
      </Card>

      <Card title={`Zmiany w ostatnim przebiegu (${data.changes_total})`}>
        <ChangeTable changes={data.recent_changes} />
        {data.changes_total > data.recent_changes.length && (
          <p className="my-2 text-muted">Pokazano {data.recent_changes.length} z {data.changes_total}. Wszystkie: zakładka Skany → Zmiany.</p>
        )}
      </Card>

      <Card title="Technologie">
        <DataTable
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
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(150px,1fr))] gap-3">
      <StatCard label="Cele" value={d.targets} />
      <StatCard label="Hosty aktywne" value={d.assets.active ?? 0} />
      <StatCard label="Hosty niestabilne" value={d.assets.unstable ?? 0} />
      <StatCard label="Hosty nieaktywne" value={d.assets.inactive ?? 0} />
      <StatCard label="Usługi" value={d.services} />
      <StatCard label="Zmiany" value={d.changes_total} />
      <StatCard label="Ostatni przebieg" value={run ? run.status : "brak"} hint={run ? formatDate(run.started_at ?? run.created_at) : undefined} />
      <StatCard label="Skan w toku" value={d.scan_running ? "tak" : "nie"} />
    </div>
  );
}
