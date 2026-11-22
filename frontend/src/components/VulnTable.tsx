import { DataTable } from "./DataTable";
import type { Severity, Vulnerability, VulnState } from "../types";

export const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: "text-red font-semibold",
  High: "text-red",
  Medium: "text-orange",
  Low: "text-accent",
  Info: "text-muted",
};

export const VULN_STATE_LABELS: Record<VulnState, string> = {
  none: "nie sprawdzano",
  pending_decision: "czeka na decyzję",
  running: "sprawdzanie...",
  done: "sprawdzone",
  failed: "błąd sprawdzania",
  skipped: "pominięte",
};

/** Podatności przebiegu: CVE, CVSS, severity, usługa, poziom dowodu. */
export function VulnTable({ rows, label }: { rows: Vulnerability[]; label: string }) {
  return (
    <DataTable
      rows={rows}
      rowKey={(v) => `${v.ip}:${v.port}/${v.proto}|${v.cve_id}`}
      label={label}
      emptyText="Brak podatności"
      columns={[
        {
          header: "CVE",
          mono: true,
          render: (v) => (
            <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noreferrer noopener">
              {v.cve_id}
            </a>
          ),
          title: (v) => v.cve_id,
        },
        {
          header: "Severity",
          render: (v) => <span className={SEVERITY_COLORS[v.severity]}>{v.severity}</span>,
          title: (v) => v.severity,
        },
        {
          header: "CVSS",
          mono: true,
          render: (v) => (v.cvss_score === null ? "bez oceny" : v.cvss_score.toFixed(1)),
          title: (v) => v.cvss_vector ?? "brak wektora CVSS",
        },
        { header: "Usługa", mono: true, render: (v) => `${v.ip}:${v.port}/${v.proto}` },
        { header: "Komponent", render: (v) => `${v.component} ${v.version}` },
        {
          header: "Dowód",
          render: (v) => (v.evidence === "confirmed" ? "potwierdzona" : "korelacja wersji"),
          title: (v) =>
            v.evidence === "confirmed"
              ? "Potwierdzona nieinwazyjnym szablonem CVE"
              : "Wersja usługi pasuje do CVE w NVD; wymaga potwierdzenia (możliwe poprawki wsteczne)",
        },
        { header: "Opis", wrap: true, render: (v) => v.description },
      ]}
    />
  );
}
