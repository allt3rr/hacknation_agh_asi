import type { Detection, Observation } from "../types";
import { DataTable, type Column } from "./DataTable";

function DetectionBadge({ detection }: { detection: Detection }) {
  const version = detection.version ? ` ${detection.version}` : "";
  return (
    <span className="mr-1 my-px inline-block rounded-full border border-line bg-bg px-2 py-px text-xs" title={detection.evidence.join(", ")}>
      {detection.name}
      {version} ({detection.confidence}%)
    </span>
  );
}

const COLUMNS: Column<Observation>[] = [
  {
    header: "Usługa",
    render: (o) => (
      <>
        {o.ip}:{o.port}/{o.proto}
        {o.hostname && <div className="text-muted">{o.hostname}</div>}
      </>
    ),
  },
  { header: "Serwis", render: (o) => [o.service, o.product, o.version].filter(Boolean).join(" ") },
  { header: "HTTP", render: (o) => o.http?.status ?? "" },
  { header: "Tytuł", render: (o) => o.http?.title ?? "" },
  {
    header: "Technologie",
    render: (o) => o.detections.map((d) => <DetectionBadge key={d.signature_id} detection={d} />),
  },
];

export function ObservationTable({ observations }: { observations: Observation[] }) {
  return (
    <DataTable
      columns={COLUMNS}
      rows={observations}
      rowKey={(o) => `${o.ip}:${o.port}/${o.proto}`}
      emptyText="Brak usług"
    />
  );
}
