import { useRef, useState } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { CustomSignature, Role } from "../types";
import { BTN_SECONDARY, formatDate } from "../utils";

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

const BADGE = "mr-1 my-px inline-block rounded-full border border-line bg-bg px-2 py-px text-xs";

export function SignaturesPage({ role }: { role: Role }) {
  const { data, error, reload } = useApiData(api.signatures.list);
  const { info, run } = useNotice();
  const [yaml, setYaml] = useState(EXAMPLE_SIGNATURE);
  /** Edytowana sygnatura; null = dodawanie nowej. */
  const [editing, setEditing] = useState<CustomSignature | null>(null);
  const canManage = can(role, "signatures");
  const editorHeading = useRef<HTMLHeadingElement>(null);

  const save = () =>
    run(async () => {
      const result = editing ? await api.signatures.update(editing.id, { yaml }) : await api.signatures.add(yaml);
      info(`Zapisano${editing ? ` zmiany w ${editing.name}` : ""}. Aktywnych sygnatur: ${result.active_signatures}`);
      setEditing(null);
      setYaml(EXAMPLE_SIGNATURE);
      await reload();
    });

  const startEdit = (signature: CustomSignature) => {
    setEditing(signature);
    setYaml(signature.yaml);
    editorHeading.current?.scrollIntoView({ block: "start" });
    editorHeading.current?.focus();
  };

  const cancelEdit = () => {
    setEditing(null);
    setYaml(EXAMPLE_SIGNATURE);
  };

  const toggle = (signature: CustomSignature, enabled: boolean) =>
    run(async () => {
      const result = await api.signatures.update(signature.id, { enabled });
      info(`${enabled ? "Włączono" : "Wyłączono"} sygnaturę ${signature.name}. Aktywnych: ${result.active_signatures}`);
      await reload();
    });

  const remove = (signature: CustomSignature) =>
    run(async () => {
      if (!confirm(`Usunąć sygnaturę ${signature.name}?`)) return;
      await api.signatures.remove(signature.id);
      await reload();
    });

  return (
    <>
      {error && (
        <p role="alert" className="my-3.5 text-red">
          {error}
        </p>
      )}

      {canManage && (
        <Card title={editing ? `Edycja sygnatury ${editing.name}` : "Dodaj własną sygnaturę (YAML)"} headingRef={editorHeading}>
          <label htmlFor="signature-yaml" className="mb-1 block">
            Definicja sygnatury
          </label>
          <textarea
            id="signature-yaml"
            className="min-h-[110px] w-full font-mono"
            rows={12}
            spellCheck={false}
            aria-describedby="signature-hint"
            value={yaml}
            onChange={(e) => setYaml(e.target.value)}
          />
          <p id="signature-hint" className="text-muted">
            Tylko bezpieczna detekcja: nagłówek, ciasteczko, tytuł, fragment HTML, hash favicony, ścieżka (bez prób logowania).
          </p>
          <div className="my-2 flex flex-wrap items-center gap-2">
            <button onClick={save} disabled={!yaml.trim()}>
              {editing ? "Zapisz zmiany" : "Zapisz"}
            </button>
            {editing && (
              <button className={BTN_SECONDARY} onClick={cancelEdit}>
                Anuluj edycję
              </button>
            )}
          </div>
        </Card>
      )}

      <Card title="Własne sygnatury">
        <DataTable
          rows={data?.custom ?? []}
          rowKey={(s) => s.id}
          label="Własne sygnatury"
          emptyText="Brak własnych sygnatur"
          columns={[
            { header: "Nazwa", render: (s) => s.name },
            { header: "Autor", render: (s) => s.created_by },
            { header: "Dodano", render: (s) => formatDate(s.created_at) },
            {
              header: "Aktywna",
              render: (s) => (
                <input
                  type="checkbox"
                  aria-label={`Sygnatura ${s.name} aktywna`}
                  checked={s.enabled !== 0}
                  disabled={!canManage}
                  onChange={(e) => toggle(s, e.target.checked)}
                />
              ),
            },
            {
              header: "",
              render: (s) =>
                canManage && (
                  <div className="flex flex-wrap gap-1">
                    <button className={BTN_SECONDARY} aria-label={`Edytuj sygnaturę ${s.name}`} onClick={() => startEdit(s)}>
                      Edytuj
                    </button>
                    <button className={BTN_SECONDARY} aria-label={`Usuń sygnaturę ${s.name}`} onClick={() => remove(s)}>
                      Usuń
                    </button>
                  </div>
                ),
            },
          ]}
        />
      </Card>

      <Card title="Aktywne sygnatury">
        <DataTable
          rows={data?.active ?? []}
          rowKey={(s) => s.id}
          label="Aktywne sygnatury"
          filterBy={(s) => [s.id, s.name, s.category].join(" ")}
          columns={[
            { header: "ID", render: (s) => s.id },
            { header: "Nazwa", render: (s) => s.name },
            { header: "Kategoria", render: (s) => <span className={BADGE}>{s.category}</span> },
            { header: "Pewność", render: (s) => `${s.confidence}%` },
            { header: "Reguły", render: (s) => s.rules.map((rule) => rule.type).join(", ") },
          ]}
        />
      </Card>
    </>
  );
}
