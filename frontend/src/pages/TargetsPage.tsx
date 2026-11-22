import { useMemo, useState } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { FilePicker } from "../components/FilePicker";
import { TagCombobox, collectTags } from "../components/TagCombobox";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { ImportSummary, Session, Target } from "../types";
import { BADGE, BTN_SECONDARY, fileFormat } from "../utils";

const PLACEHOLDER = "10.0.0.0/24\n192.168.1.10\nintranet.example.pl";

function summaryText(s: ImportSummary): string {
  const rejected = s.rejected.length
    ? `, odrzucono ${s.rejected.length}: ${s.rejected.slice(0, 10).map((r) => `${r.value} (wiersz ${r.row})`).join(", ")}`
    : "";
  return `Dodano celów: ${s.accepted}. Wierszy: ${s.rows}, duplikatów: ${s.duplicates}${rejected}`;
}

export function TargetsPage({ session }: { session: Session }) {
  const { data: targets, error, reload } = useApiData(api.targets.list);
  const { info, run } = useNotice();
  const [text, setText] = useState("");
  const [tagFilter, setTagFilter] = useState<string | null>(null);
  const all = useMemo(() => targets ?? [], [targets]);
  const tags = useMemo(() => collectTags(all), [all]);
  const rows = tagFilter ? all.filter((t) => t.tags.includes(tagFilter)) : all;

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
      {can(session, "targets.create") && (
        <Card title="Dodaj cele">
          <label htmlFor="targets-text" className="mb-1 block">
            Adresy IP, zakresy CIDR lub domeny, po jednym w wierszu
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
            <span className="text-xs text-muted" title="CSV: kolumny target, tags, note albo plik organizatora z kolumną ip_address">
              plik CSV/JSON/TXT:
            </span>
            <FilePicker accept=".csv,.json,.txt" label="Plik z celami (CSV, JSON lub TXT)" buttonLabel="Importuj plik" onSubmit={importFile} />
          </div>
        </Card>
      )}

      <Card
        title={tagFilter ? `Lista celów (${rows.length}/${all.length})` : `Lista celów (${all.length})`}
        actions={<TagCombobox tags={tags} value={tagFilter} onSelect={setTagFilter} label="Filtr: tag" placeholder="wszystkie tagi" clearLabel="wszystkie tagi" />}
      >
        {error && (
          <p role="alert" className="my-3.5 text-red">
            {error}
          </p>
        )}
        <TargetTable targets={rows} tags={tags} session={session} onChanged={reload} run={run} />
      </Card>
    </>
  );
}

interface TargetTableProps {
  targets: Target[];
  /** Wszystkie tagi z listy celów (podpowiedzi w comboboxie). */
  tags: string[];
  session: Session;
  onChanged: () => Promise<void>;
  run: (action: () => Promise<void>) => Promise<void>;
}

function TargetTable({ targets, tags, session, onChanged, run }: TargetTableProps) {
  const canTag = can(session, "targets.update");
  const setTags = (target: Target, next: string[]) =>
    run(async () => {
      await api.targets.update(target.id, { tags: next });
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
      filterBy={(t) => `${t.value} ${t.kind} ${t.tags.join(" ")}`}
      columns={[
        { header: "Cel", mono: true, render: (t) => t.value },
        { header: "Typ", render: (t) => (t.excluded ? `${t.kind} · wykluczony` : t.kind) },
        {
          header: "Tagi",
          wrap: true,
          render: (t) => (
            <div className="flex flex-wrap items-center gap-1">
              {t.tags.map((tag) => (
                <span key={tag} className={`${BADGE} mono`}>
                  {tag}
                  {canTag && (
                    <button
                      type="button"
                      className="ml-1 border-0 bg-transparent p-0 text-muted shadow-none hover:text-red"
                      aria-label={`Usuń tag ${tag} z celu ${t.value}`}
                      onClick={() => setTags(t, t.tags.filter((x) => x !== tag))}
                    >
                      ×
                    </button>
                  )}
                </span>
              ))}
              {canTag && (
                <TagCombobox
                  tags={tags.filter((tag) => !t.tags.includes(tag))}
                  value={null}
                  onSelect={(tag) => tag && !t.tags.includes(tag) && setTags(t, [...t.tags, tag])}
                  label={`Dodaj tag do celu ${t.value}`}
                  placeholder="+ tag"
                  allowCreate
                />
              )}
            </div>
          ),
        },
        ...(can(session, "targets.delete")
          ? [
              {
                header: "",
                render: (t: Target) => (
                  <button className={BTN_SECONDARY} aria-label={`Usuń cel ${t.value}`} onClick={() => remove(t)}>
                    Usuń
                  </button>
                ),
              },
            ]
          : []),
      ]}
    />
  );
}
