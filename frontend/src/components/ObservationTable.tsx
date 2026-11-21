import { api } from "../api";
import { EditableText } from "../pages/TargetsPage";
import type { Detection, ResultRow } from "../types";
import { BADGE, errorMessage } from "../utils";
import { DataTable, type Column } from "./DataTable";

const STATUSES = ["", "open", "false_positive", "accepted", "fixed"];

function DetectionBadge({ detection }: { detection: Detection }) {
  const version = detection.version ? ` ${detection.version}` : "";
  return (
    <span className={BADGE} title={detection.evidence.join(", ")}>
      {detection.name}
      {version} ({detection.confidence}%)
    </span>
  );
}

function serviceText(o: { service: string | null; product: string | null; version: string | null }) {
  return [o.service, o.product, o.version].filter(Boolean).join(" ");
}

interface Props {
  rows: ResultRow[];
  /** Użytkownik może zapisywać korekty (`data.update`). */
  editable: boolean;
  onChanged: () => void;
  onError: (message: string) => void;
}

/** Usługi przebiegu po korektach analityka; surowy pomiar widoczny, gdy korekta go zmienia. */
export function ObservationTable({ rows, editable, onChanged, onError }: Props) {
  const save = (row: ResultRow, field: string, value: string) => {
    const action = value ? api.overrides.set(row.key, field, value) : api.overrides.remove(row.key, field);
    action.then(onChanged, (e) => onError(errorMessage(e)));
  };

  const columns: Column<ResultRow>[] = [
    {
      header: "Usługa",
      render: (o) => (
        <>
          {o.key}
          {o.hostname && <div className="text-muted">{o.hostname}</div>}
        </>
      ),
    },
    {
      header: "Serwis",
      render: (o) => {
        const raw = serviceText({ service: o.raw_service, product: o.raw_product, version: o.raw_version });
        const shown = serviceText(o);
        return (
          <>
            {shown}
            {raw !== shown && <div className="text-muted" title="surowy pomiar">pomiar: {raw}</div>}
          </>
        );
      },
    },
    { header: "HTTP", render: (o) => o.http?.status ?? "" },
    {
      header: "Tytuł / ciasteczka",
      render: (o) => (
        <>
          {o.http?.title ?? ""}
          {o.http && o.http.cookies.length > 0 && (
            <div className="text-muted">{o.http.cookies.map((c) => `${c.name} [${c.attributes.join("; ")}]`).join(", ")}</div>
          )}
        </>
      ),
    },
    { header: "Technologie", render: (o) => o.technologies.map((d) => <DetectionBadge key={d.signature_id} detection={d} />) },
    {
      header: "Status",
      render: (o) =>
        editable ? (
          <select aria-label={`Status ${o.key}`} value={o.status ?? ""} onChange={(e) => save(o, "status", e.target.value)}>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s || "—"}
              </option>
            ))}
          </select>
        ) : (
          o.status ?? ""
        ),
    },
    {
      header: "Notatka",
      render: (o) => (editable ? <EditableText label={`Notatka ${o.key}`} value={o.note ?? ""} onSave={(v) => save(o, "note", v)} /> : o.note),
    },
  ];

  return <DataTable columns={columns} rows={rows} rowKey={(o) => o.id} emptyText="Brak usług" />;
}
