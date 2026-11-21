import { useState } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { FilePicker } from "../components/FilePicker";
import { NoticeBar } from "../components/NoticeBar";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { ImportSummary, Role, Target, TargetPatch } from "../types";
import { BTN_SECONDARY, fileFormat } from "../utils";

const PLACEHOLDER = "10.0.0.0/24\n192.168.1.10\nintranet.example.pl";

function summaryText(summary: ImportSummary): string {
  const rejected = summary.invalid.length ? `, odrzucono: ${summary.invalid.join(", ")}` : "";
  return `Dodano ${summary.inserted} z ${summary.parsed}${rejected}`;
}

export function TargetsPage({ role }: { role: Role }) {
  const { data: targets, error, reload } = useApiData(api.targets.list);
  const { notice, info, run } = useNotice();
  const [text, setText] = useState("");

  const addManually = () =>
    run(async () => {
      info(summaryText(await api.targets.addText(text)));
      setText("");
      await reload();
    });

  const importFile = (file: File) =>
    run(async () => {
      info(summaryText(await api.targets.importFile(fileFormat(file.name), await file.text())));
      await reload();
    });

  return (
    <>
      <NoticeBar notice={notice} />

      {can(role, "create") && (
        <Card title="Dodaj cele">
          <textarea className="min-h-[110px] w-full" placeholder={PLACEHOLDER} value={text} onChange={(e) => setText(e.target.value)} />
          <div className="my-2 flex flex-wrap items-center gap-2">
            <button onClick={addManually} disabled={!text.trim()}>
              Dodaj ręcznie
            </button>
            <span className="text-muted">lub plik CSV (target,tags,note), JSON albo TXT:</span>
            <FilePicker accept=".csv,.json,.txt" buttonLabel="Importuj plik" onSubmit={importFile} />
          </div>
        </Card>
      )}

      <Card title="Lista celów">
        {error && <p className="my-3.5 text-red">{error}</p>}
        <TargetTable targets={targets ?? []} role={role} onChanged={reload} run={run} />
      </Card>
    </>
  );
}

interface TargetTableProps {
  targets: Target[];
  role: Role;
  onChanged: () => Promise<void>;
  /** Wykonuje akcję i pokazuje ewentualny błąd (z useNotice). */
  run: (action: () => Promise<void>) => Promise<void>;
}

function TargetTable({ targets, role, onChanged, run }: TargetTableProps) {
  const editable = can(role, "modify");

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
      columns={[
        { header: "Cel", render: (t) => t.value },
        { header: "Typ", render: (t) => t.kind },
        {
          header: "Tagi",
          render: (t) =>
            editable ? (
              <EditableText
                value={t.tags.join(", ")}
                onSave={(value) => update(t, { tags: value.split(",").map((s) => s.trim()).filter(Boolean) })}
              />
            ) : (
              t.tags.join(", ")
            ),
        },
        {
          header: "Notatka",
          render: (t) =>
            editable ? <EditableText value={t.note ?? ""} onSave={(note) => update(t, { note })} /> : t.note,
        },
        {
          header: "Skanowany",
          render: (t) => (
            <input
              type="checkbox"
              checked={t.enabled}
              disabled={!editable}
              onChange={(e) => update(t, { enabled: e.target.checked })}
            />
          ),
        },
        {
          header: "",
          render: (t) =>
            can(role, "delete") && (
              <button className={BTN_SECONDARY} onClick={() => remove(t)}>
                Usuń
              </button>
            ),
        },
      ]}
    />
  );
}

/** Pole tekstowe zapisywane po opuszczeniu (blur), tylko jeśli wartość się zmieniła. */
function EditableText({ value, onSave }: { value: string; onSave: (value: string) => void }) {
  const [draft, setDraft] = useState(value);
  return (
    <input
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={() => draft !== value && onSave(draft)}
    />
  );
}
