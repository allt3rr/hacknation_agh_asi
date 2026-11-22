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
  { header: "Usługa / host", mono: true, render: (c) => c.entity_key },
  { header: "Pole", render: (c) => c.field ?? "" },
  { header: "Przed", mono: true, render: (c) => c.before ?? "" },
  { header: "Po", mono: true, render: (c) => c.after ?? "" },
];

export function ChangeTable({ changes, label = "Zmiany" }: { changes: Change[]; label?: string }) {
  return (
    <DataTable
      columns={COLUMNS}
      rows={changes}
      rowKey={(c, i) => `${c.id ?? i}-${c.entity_key}-${c.kind}`}
      emptyText="Brak zmian"
      label={label}
      filterBy={(c) => [KIND_LABELS[c.kind], c.entity_key, c.field, c.before, c.after].join(" ")}
    />
  );
}
