import { useState } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { NoticeBar } from "../components/NoticeBar";
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

export function SignaturesPage({ role }: { role: Role }) {
  const { data, error, reload } = useApiData(api.signatures.list);
  const { notice, info, run } = useNotice();
  const [yaml, setYaml] = useState(EXAMPLE_SIGNATURE);
  const canManage = can(role, "signatures");

  const save = () =>
    run(async () => {
      const result = await api.signatures.add(yaml);
      info(`Zapisano. Aktywnych sygnatur: ${result.active_signatures}`);
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
      <NoticeBar notice={notice} />
      {error && <p className="my-3.5 text-red">{error}</p>}

      {canManage && (
        <Card title="Dodaj własną sygnaturę (YAML)">
          <textarea className="min-h-[110px] w-full font-mono" rows={12} value={yaml} onChange={(e) => setYaml(e.target.value)} />
          <div className="my-2 flex flex-wrap items-center gap-2">
            <button onClick={save}>Zapisz</button>
          </div>
        </Card>
      )}

      <Card title="Własne sygnatury">
        <DataTable
          rows={data?.custom ?? []}
          rowKey={(s) => s.id}
          columns={[
            { header: "Nazwa", render: (s) => s.name },
            { header: "Autor", render: (s) => s.created_by },
            { header: "Dodano", render: (s) => formatDate(s.created_at) },
            {
              header: "",
              render: (s) =>
                canManage && (
                  <button className={BTN_SECONDARY} onClick={() => remove(s)}>
                    Usuń
                  </button>
                ),
            },
          ]}
        />
      </Card>

      <Card title="Aktywne sygnatury">
        <DataTable
          rows={data?.active ?? []}
          rowKey={(s) => s.id}
          columns={[
            { header: "ID", render: (s) => s.id },
            { header: "Nazwa", render: (s) => s.name },
            { header: "Kategoria", render: (s) => <span className="mr-1 my-px inline-block rounded-full border border-line bg-bg px-2 py-px text-xs">{s.category}</span> },
            { header: "Pewność", render: (s) => `${s.confidence}%` },
            { header: "Reguły", render: (s) => s.rules.map((rule) => rule.type).join(", ") },
          ]}
        />
      </Card>
    </>
  );
}
