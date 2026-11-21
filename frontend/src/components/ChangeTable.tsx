import type { Change, ChangeKind } from "../types";
import { DataTable, type Column } from "./DataTable";

const KIND_LABELS: Record<ChangeKind, string> = {
  new: "nowa",
  gone: "zniknęła",
  changed: "zmiana",
  host_inactive: "host nieaktywny",
  host_returned: "host wrócił",
};

const KIND_COLORS: Record<ChangeKind, string> = {
  new: "text-green",
  gone: "text-red",
  changed: "text-orange",
  host_inactive: "text-red",
  host_returned: "text-accent",
};

const COLUMNS: Column<Change>[] = [
  { header: "Typ", render: (c) => <span className={`font-medium ${KIND_COLORS[c.kind]}`}>{KIND_LABELS[c.kind]}</span> },
  { header: "Usługa / host", render: (c) => c.key },
  { header: "Pole", render: (c) => c.field ?? "" },
  { header: "Przed", render: (c) => c.before ?? "" },
  { header: "Po", render: (c) => c.after ?? "" },
];

export function ChangeTable({ changes, label = "Zmiany" }: { changes: Change[]; label?: string }) {
  return (
    <DataTable
      columns={COLUMNS}
      rows={changes}
      rowKey={(c, i) => `${c.key}-${c.kind}-${c.field ?? ""}-${i}`}
      emptyText="Brak zmian"
      label={label}
      filterBy={(c) => [KIND_LABELS[c.kind], c.key, c.field, c.before, c.after].join(" ")}
    />
  );
}
