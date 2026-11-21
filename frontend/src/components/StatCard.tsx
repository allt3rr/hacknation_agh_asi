import type { ReactNode } from "react";

type Tone = "accent" | "green" | "orange" | "red" | "muted";

const TONES: Record<Tone, string> = {
  accent: "text-accent bg-accent/10",
  green: "text-green bg-green/10",
  orange: "text-orange bg-orange/10",
  red: "text-red bg-red/10",
  muted: "text-muted bg-surface-2",
};

interface StatCardProps {
  label: string;
  value: ReactNode;
  hint?: string;
  icon?: ReactNode;
  tone?: Tone;
}

/** Kafel KPI: liczba, opis i ikona w kolorze znaczenia (kolor nigdy nie jest jedyną informacją). */
export function StatCard({ label, value, hint, icon, tone = "accent" }: StatCardProps) {
  return (
    <div className="flex flex-col items-start gap-2 rounded-xl border border-line bg-surface/60 p-3 sm:flex-row sm:gap-3 transition-colors hover:border-accent/40">
      {icon && <span className={`grid size-9 shrink-0 place-items-center rounded-lg ${TONES[tone]}`}>{icon}</span>}
      <div className="min-w-0">
        <div className="text-2xl leading-tight font-semibold tabular-nums">{value}</div>
        <div className="text-muted">{label}</div>
        {hint && <div className="text-xs text-muted">{hint}</div>}
      </div>
    </div>
  );
}
