import { useState } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { FilePicker } from "../components/FilePicker";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { ImportSummary, Session, Target, TargetPatch } from "../types";
import { BTN_SECONDARY, fileFormat } from "../utils";

const PLACEHOLDER = "10.0.0.0/24\n192.168.1.10\nintranet.example.pl";

function summaryText(s: ImportSummary): string {
  const rejected = s.rejected.length
    ? `, odrzucono ${s.rejected.length}: ${s.rejected.slice(0, 10).map((r) => `${r.value} (wiersz ${r.row})`).join(", ")}`
    : "";
  const prefix = s.dry_run ? "Podgląd: zostałoby dodanych" : "Dodano";
  return `${prefix} ${s.accepted} (wierszy: ${s.rows}, duplikatów: ${s.duplicates}${rejected})`;
}

export function TargetsPage({ session }: { session: Session }) {
  const { data: targets, error, reload } = useApiData(api.targets.list);
  const { info, run } = useNotice();
  const [text, setText] = useState("");
  const [dryRun, setDryRun] = useState(false);

  const addManually = () =>
    run(async () => {
      info(summaryText(await api.targets.addText(text)));
      setText("");
      await reload();
    });

  const importFile = (file: File) =>
    run(async () => {
      info(summaryText(await api.targets.importFile(fileFormat(file.name), await file.text(), dryRun)));
      await reload();
    });

  return (
    <>
      {can(session, "targets.create") && (
        <Card title="Dodaj cele">
          <label htmlFor="targets-text" className="mb-1 block">
            Adresy IP, zakresy CIDR lub domeny (jeden na linię)
          </label>
          <textarea
            id="targets-text"
            className="min-h-[110px] w-full font-mono"
            placeholder={PLACEHOLDER}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <div className="my-2 flex flex-wrap items-center gap-2">
            <button onClick={addManually} disabled={!text.trim()}>
              Dodaj ręcznie
            </button>
            <span className="text-muted">lub plik CSV (target,tags,note albo format organizatora z ip_address), JSON, TXT:</span>
            <FilePicker accept=".csv,.json,.txt" label="Plik z celami (CSV, JSON lub TXT)" buttonLabel="Importuj plik" onSubmit={importFile} />
            <label className="text-muted">
              <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} /> tylko podgląd
            </label>
          </div>
        </Card>
      )}

      <Card title={`Lista celów (${targets?.length ?? 0})`}>
        {error && (
          <p role="alert" className="my-3.5 text-red">
            {error}
          </p>
        )}
        <TargetTable targets={targets ?? []} session={session} onChanged={reload} run={run} />
      </Card>
    </>
  );
}

interface TargetTableProps {
  targets: Target[];
  session: Session;
  onChanged: () => Promise<void>;
  run: (action: () => Promise<void>) => Promise<void>;
}

function TargetTable({ targets, session, onChanged, run }: TargetTableProps) {
  const editable = can(session, "targets.update");

  const update = (target: Target, patch: TargetPatch) =>
    run(async () => {
      await api.targets.update(target.id, patch);
      await onChanged();
    });

  const remove = (target: Target) =>
    run(async () => {
      if (!confirm(`Usunąć cel ${target.value}?`)) return;
      await api.targets.remove(target.id);
      await onChanged();
    });

  return (
    <DataTable
      rows={targets}
      rowKey={(t) => t.id}
      label="Lista celów"
      emptyText="Brak celów"
      filterBy={(t) => [t.value, t.kind, ...t.tags, t.note].join(" ")}
      columns={[
        { header: "Cel", render: (t) => t.value },
        { header: "Typ", render: (t) => t.kind },
        {
          header: "Tagi",
          render: (t) =>
            editable ? (
              <EditableText
                label={`Tagi celu ${t.value}`}
                value={t.tags.join(", ")}
                onSave={(value) => update(t, { tags: value.split(",").map((s) => s.trim()).filter(Boolean) })}
              />
            ) : (
              t.tags.join(", ")
            ),
        },
        {
          header: "Notatka",
          render: (t) => (editable ? <EditableText label={`Notatka celu ${t.value}`} value={t.note ?? ""} onSave={(note) => update(t, { note })} /> : t.note),
        },
        {
          header: "Skanowany",
          render: (t) => (
            <input
              type="checkbox"
              aria-label={`Skanuj ${t.value}`}
              checked={!t.excluded}
              disabled={!editable}
              onChange={(e) => update(t, { excluded: !e.target.checked })}
            />
          ),
        },
        {
          header: "",
          render: (t) =>
            can(session, "targets.delete") && (
              <button className={BTN_SECONDARY} aria-label={`Usuń cel ${t.value}`} onClick={() => remove(t)}>
                Usuń
              </button>
            ),
        },
      ]}
    />
  );
}

/** Pole tekstowe zapisywane po opuszczeniu (blur) lub Enter, tylko jeśli wartość się zmieniła. */
export function EditableText({ value, onSave, label }: { value: string; onSave: (value: string) => void; label: string }) {
  const [draft, setDraft] = useState(value);
  return (
    <input
      aria-label={label}
      title="Zapis po wyjściu z pola lub klawiszem Enter"
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      onKeyDown={(e) => e.key === "Enter" && e.currentTarget.blur()}
      onBlur={() => draft !== value && onSave(draft)}
    />
  );
}
