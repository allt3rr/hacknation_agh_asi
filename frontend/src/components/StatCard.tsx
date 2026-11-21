import type { ReactNode } from "react";

interface StatCardProps {
  label: string;
  value: ReactNode;
  hint?: string;
}

export function StatCard({ label, value, hint }: StatCardProps) {
  return (
    <div>
      <div className="text-2xl font-semibold">{value}</div>
      <div className="text-muted">{label}</div>
      {hint && <div className="text-xs text-muted">{hint}</div>}
    </div>
  );
}
