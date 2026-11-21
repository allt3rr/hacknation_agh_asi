import { useState } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { NoticeBar } from "../components/NoticeBar";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { Session, SignatureList } from "../types";
import { BADGE, BTN_SECONDARY, formatDate } from "../utils";

const EXAMPLE_SIGNATURE = `- id: moja-aplikacja
  name: Moja aplikacja
  category: application
  confidence: 80
  rules:
    - type: header
      name: x-app-name
      regex: 'moja'
    - type: title
      regex: 'Moja Aplikacja'`;

type Custom = SignatureList["custom"][number];

export function SignaturesPage({ session }: { session: Session }) {
  const { data, error, reload } = useApiData(api.signatures.list);
  const { notice, info, run } = useNotice();
  const [yaml, setYaml] = useState(EXAMPLE_SIGNATURE);
  // slug edytowanej sygnatury (PUT = nowa wersja) albo null przy dodawaniu
  const [editing, setEditing] = useState<string | null>(null);
  const canWrite = editing ? can(session, "signatures.update") : can(session, "signatures.create");

  const save = () =>
    run(async () => {
      if (editing) {
        await api.signatures.update(editing, yaml);
        info(`Zapisano nową wersję sygnatury ${editing}`);
      } else {
        const res = await api.signatures.add(yaml);
        info(`Dodano: ${res.created.join(", ")}`);
      }
      setEditing(null);
      await reload();
    });

  const edit = (s: Custom) => {
    setEditing(s.slug);
    setYaml(s.yaml);
  };

  const disable = (s: Custom) =>
    run(async () => {
      if (!confirm(`Wyłączyć sygnaturę ${s.slug}?`)) return;
      await api.signatures.disable(s.slug);
      await reload();
    });

  return (
    <>
      <NoticeBar notice={notice} />
      {error && <p className="my-3.5 text-red">{error}</p>}

      {(can(session, "signatures.create") || editing) && (
        <Card title={editing ? `Edycja sygnatury ${editing}` : "Dodaj własną sygnaturę (YAML)"}>
          <textarea aria-label="YAML sygnatury" className="min-h-[110px] w-full font-mono" rows={12} value={yaml} onChange={(e) => setYaml(e.target.value)} />
          <div className="my-2 flex flex-wrap items-center gap-2">
            <button onClick={save} disabled={!canWrite}>
              Zapisz
            </button>
            {editing && (
              <button className={BTN_SECONDARY} onClick={() => { setEditing(null); setYaml(EXAMPLE_SIGNATURE); }}>
                Anuluj edycję
              </button>
            )}
            <span className="text-muted">Ścieżki reguł `path` muszą zaczynać się od „/” (bez innego hosta).</span>
          </div>
        </Card>
      )}

      <Card title="Własne sygnatury">
        <DataTable
          rows={data?.custom ?? []}
          rowKey={(s) => s.slug}
          columns={[
            { header: "ID", render: (s) => s.slug },
            { header: "Wersja", render: (s) => s.version },
            { header: "Stan", render: (s) => (s.enabled ? "aktywna" : "wyłączona") },
            { header: "Zmieniono", render: (s) => formatDate(s.created_at) },
            {
              header: "",
              render: (s) => (
                <div className="flex gap-1">
                  {can(session, "signatures.update") && (
                    <button className={BTN_SECONDARY} onClick={() => edit(s)}>
                      Edytuj
                    </button>
                  )}
                  {can(session, "signatures.delete") && s.enabled && (
                    <button className={BTN_SECONDARY} onClick={() => disable(s)}>
                      Wyłącz
                    </button>
                  )}
                </div>
              ),
            },
          ]}
        />
      </Card>

      <Card title={`Wbudowane sygnatury (${data?.builtin.length ?? 0})`}>
        <DataTable
          rows={data?.builtin ?? []}
          rowKey={(s) => s.id}
          columns={[
            { header: "ID", render: (s) => s.id },
            { header: "Nazwa", render: (s) => s.name },
            { header: "Kategoria", render: (s) => <span className={BADGE}>{s.category}</span> },
          ]}
        />
      </Card>
    </>
  );
}
