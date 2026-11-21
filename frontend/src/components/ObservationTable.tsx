import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { INTEREST_HINT, interestLabel, interestScore } from "../interest";
import { EditableText } from "../pages/TargetsPage";
import type { Detection, ResultRow } from "../types";
import { BADGE, BTN_SECONDARY, errorMessage } from "../utils";
import { DataTable, type Column } from "./DataTable";

const STATUSES = ["", "open", "false_positive", "accepted", "fixed"];

function DetectionBadge({ detection }: { detection: Detection }) {
  const version = detection.version ? ` ${detection.version}` : "";
  return (
    <span className={BADGE}>
      {detection.name}
      {version} ({detection.confidence}%)
    </span>
  );
}

function serviceText(o: { service: string | null; product: string | null; version: string | null }) {
  return [o.service, o.product, o.version].filter(Boolean).join(" ");
}

interface ServiceGroup {
  name: string;
  members: ResultRow[];
  technologies: string[];
  topScore: number;
}

/** Grupowanie podobnych usług: ten sam serwis, produkt i wersja. */
function groupServices(rows: ResultRow[]): ServiceGroup[] {
  const groups = new Map<string, ServiceGroup>();
  for (const row of rows) {
    const name = serviceText(row) || "nieznana usługa";
    const group = groups.get(name) ?? { name, members: [], technologies: [], topScore: 0 };
    group.members.push(row);
    for (const d of row.technologies) {
      if (!group.technologies.includes(d.name)) group.technologies.push(d.name);
    }
    group.topScore = Math.max(group.topScore, interestScore(row));
    groups.set(name, group);
  }
  return [...groups.values()].sort((a, b) => b.members.length - a.members.length);
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
  const [selected, setSelected] = useState<ResultRow | null>(null);
  const [grouped, setGrouped] = useState(false);
  // Najciekawsze usługi na górze (w obrębie bieżącej strony wyników).
  const sorted = useMemo(() => [...rows].sort((a, b) => interestScore(b) - interestScore(a)), [rows]);

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
      header: "Ocena",
      render: (o) => {
        const value = interestScore(o);
        return (
          <span className={value >= 60 ? "font-semibold text-red" : value >= 30 ? "font-medium text-orange" : "text-muted"}>
            {value} ({interestLabel(value)})
          </span>
        );
      },
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
    {
      header: "",
      render: (o) => (
        <button className={BTN_SECONDARY} aria-label={`Szczegóły usługi ${o.key}`} onClick={() => setSelected(o)}>
          Szczegóły
        </button>
      ),
    },
  ];

  return (
    <>
      <div className="my-2 flex flex-wrap items-center gap-2">
        <label className="inline-flex items-center gap-1">
          <input type="checkbox" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />
          Grupuj podobne usługi
        </label>
        <span className="text-muted" title={INTEREST_HINT}>
          Sortowanie wg oceny priorytetu (najciekawsze na górze).
        </span>
      </div>

      {grouped ? (
        <DataTable
          label="Grupy podobnych usług"
          rows={groupServices(sorted)}
          rowKey={(g) => g.name}
          filterBy={(g) => [g.name, ...g.technologies].join(" ")}
          columns={[
            { header: "Usługa", render: (g) => g.name },
            { header: "Liczba", render: (g) => g.members.length },
            { header: "Technologie", render: (g) => g.technologies.join(", ") },
            { header: "Najwyższa ocena", render: (g) => `${g.topScore} (${interestLabel(g.topScore)})` },
            {
              header: "Przykłady",
              render: (g) => g.members.slice(0, 5).map((m) => m.key).join(", ") + (g.members.length > 5 ? ` i ${g.members.length - 5} więcej` : ""),
            },
          ]}
        />
      ) : (
        <DataTable
          columns={columns}
          rows={sorted}
          rowKey={(o) => o.id}
          emptyText="Brak usług"
          label="Usługi"
          filterBy={(o) => [o.key, o.hostname, serviceText(o), o.http?.title, o.status, o.note, ...o.technologies.map((d) => d.name)].join(" ")}
        />
      )}
      {selected && <ObservationDetails key={selected.id} row={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function ObservationDetails({ row: o, onClose }: { row: ResultRow; onClose: () => void }) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const http = o.http;

  useEffect(() => {
    headingRef.current?.focus();
    headingRef.current?.scrollIntoView({ block: "start" });
  }, []);

  return (
    <section className="mt-3 rounded-[10px] border border-line bg-bg p-3" aria-labelledby="observation-details">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h3 id="observation-details" ref={headingRef} tabIndex={-1} className="font-bold outline-none">
          Szczegóły: {o.key}
        </h3>
        <button className={BTN_SECONDARY} onClick={onClose}>
          Zamknij szczegóły
        </button>
      </div>

      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 [&_dt]:text-muted [&_dd]:break-all">
        <dt>Host</dt>
        <dd>{o.hostname ?? o.ip}</dd>
        <dt>Stan</dt>
        <dd>{o.state}</dd>
        <dt>Serwis</dt>
        <dd>{serviceText(o) || "—"}</dd>
        {o.severity && (
          <>
            <dt>Priorytet</dt>
            <dd>{o.severity}</dd>
          </>
        )}
        {http && (
          <>
            <dt>Kod HTTP</dt>
            <dd>{http.status}</dd>
            <dt>Tytuł strony</dt>
            <dd>{http.title ?? "—"}</dd>
            <dt>URL końcowy</dt>
            <dd>{http.final_url}</dd>
            <dt>Przekierowania</dt>
            <dd>{http.redirects.length ? http.redirects.join(" → ") : "brak"}</dd>
            {http.blocked_redirects.length > 0 && (
              <>
                <dt>Zablokowane przekierowania</dt>
                <dd>{http.blocked_redirects.join(", ")}</dd>
              </>
            )}
          </>
        )}
      </dl>

      {o.technologies.length > 0 && (
        <>
          <h4 className="mt-3 font-semibold">Wykryte technologie i dowody</h4>
          <ul className="list-disc pl-5">
            {o.technologies.map((d) => (
              <li key={d.signature_id}>
                {d.name}
                {d.version ? ` ${d.version}` : ""} [{d.category}], pewność {d.confidence}%
                {d.evidence.length > 0 && <span className="text-muted">: {d.evidence.join("; ")}</span>}
              </li>
            ))}
          </ul>
        </>
      )}

      {http && (
        <>
          <h4 className="mt-3 font-semibold">Nagłówki ({Object.keys(http.headers).length})</h4>
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 font-mono text-xs [&_dd]:break-all">
            {Object.entries(http.headers).map(([name, value]) => (
              <div key={name} className="contents">
                <dt className="text-muted">{name}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
          <h4 className="mt-3 font-semibold">Ciasteczka ({http.cookies.length})</h4>
          {http.cookies.length ? (
            <ul className="list-disc pl-5 font-mono text-xs break-all">
              {http.cookies.map((c) => (
                <li key={c.name}>
                  {c.name} {c.attributes.length > 0 && <span className="text-muted">[{c.attributes.join("; ")}]</span>}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted">brak</p>
          )}
        </>
      )}
    </section>
  );
}
