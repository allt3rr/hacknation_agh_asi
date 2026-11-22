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

export const EVIDENCE_LABELS: Record<Vulnerability["evidence"], { label: string; hint: string; className: string }> = {
  confirmed: {
    label: "potwierdzona",
    hint: "Potwierdzona aktywnie nieinwazyjnym szablonem CVE (nuclei)",
    className: "text-red font-medium",
  },
  version_match: {
    label: "dokładna wersja",
    hint: "Wersja upstream usługi mieści się w zakresie podatnych wersji w NVD; wymaga potwierdzenia",
    className: "",
  },
  version_backport: {
    label: "pakiet dystrybucji",
    hint: "Wersja pakietu dystrybucji (np. Ubuntu, Debian, RHEL): poprawka mogła zostać przeniesiona wstecz — sprawdź wersję pakietu",
    className: "text-muted",
  },
  version_conditional: {
    label: "warunkowa",
    hint: "CVE dotyczy tylko konfiguracji z innym komponentem (np. system, moduł) — szczegóły w opisie",
    className: "text-muted",
  },
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
          render: (v) => <span className={EVIDENCE_LABELS[v.evidence].className}>{EVIDENCE_LABELS[v.evidence].label}</span>,
          title: (v) => EVIDENCE_LABELS[v.evidence].hint,
        },
        { header: "Opis", wrap: true, render: (v) => v.description },
      ]}
    />
  );
}
