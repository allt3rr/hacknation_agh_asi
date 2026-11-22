import type { Run } from "../types";
import { BTN_SECONDARY, formatDuration, progressEta } from "../utils";

interface ScanProgressProps {
  run: Run;
  /** Podany tylko dla roli z `scans.run`; bez niego przycisk przerwania nie jest wyświetlany. */
  onCancel?: () => void;
}

/** Pasek postępu trwającego przebiegu. Liczby są w tekście; pasek je tylko ilustruje. */
export function ScanProgress({ run, onCancel }: ScanProgressProps) {
  const { percent, etaMs, elapsedMs } = progressEta(run, Date.now());
  const label = `Postęp skanu: ${run.hosts_done} z ${run.hosts_total} celów`;
  return (
    <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded border border-accent/40 bg-surface px-3 py-2">
      <span className="flex items-center gap-2 font-semibold text-accent">
        <span aria-hidden="true" className="animate-pulse-dot size-2 rounded-full bg-accent" />
        skan w toku
      </span>
      <div
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={run.hosts_total || undefined}
        aria-valuenow={percent === null ? undefined : run.hosts_done}
        className="h-2 min-w-40 flex-1 overflow-hidden rounded-sm bg-surface-2"
      >
        <div
          className={`h-full bg-accent transition-[width] duration-500 ${percent === null ? "animate-pulse-dot w-full opacity-40" : ""}`}
          style={percent === null ? undefined : { width: `${percent}%` }}
        />
      </div>
      <dl className="mono flex flex-wrap gap-x-4 text-xs">
        <Item term="cele" value={percent === null ? "planowanie…" : `${run.hosts_done}/${run.hosts_total} (${percent}%)`} />
        <Item term="czas" value={formatDuration(elapsedMs)} />
        <Item term="ETA" value={etaMs === null ? "—" : `~${formatDuration(etaMs)}`} />
      </dl>
      {onCancel && (
        <button className={BTN_SECONDARY} onClick={onCancel}>
          Przerwij
        </button>
      )}
    </div>
  );
}

function Item({ term, value }: { term: string; value: string }) {
  return (
    <div className="flex gap-1.5 whitespace-nowrap">
      <dt className="text-muted">{term}</dt>
      <dd>{value}</dd>
    </div>
  );
}
