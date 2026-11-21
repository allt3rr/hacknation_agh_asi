import type { Change, ChangeKind } from "../types";
import { DataTable, type Column } from "./DataTable";

const KIND_LABELS: Record<ChangeKind, string> = {
  new: "nowa",
  gone: "zniknęła",
  changed: "zmiana",
  host_inactive: "host nieaktywny",
  host_returned: "host wrócił",
};

const COLUMNS: Column<Change>[] = [
  { header: "Typ", render: (c) => <span className={`kind kind-${c.kind}`}>{KIND_LABELS[c.kind]}</span> },
  { header: "Usługa / host", render: (c) => c.key },
  { header: "Pole", render: (c) => c.field ?? "" },
  { header: "Przed", render: (c) => c.before ?? "" },
  { header: "Po", render: (c) => c.after ?? "" },
];

export function ChangeTable({ changes }: { changes: Change[] }) {
  return (
    <DataTable
      columns={COLUMNS}
      rows={changes}
      rowKey={(c, i) => `${c.key}-${c.kind}-${c.field ?? ""}-${i}`}
      emptyText="Brak zmian"
    />
  );
}
