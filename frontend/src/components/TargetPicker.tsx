import { useMemo, useState } from "react";
import type { Target } from "../types";
import { BTN_SECONDARY, toggleAll } from "../utils";

const PAGE = 5;

interface TargetPickerProps {
  targets: Target[];
  /** Trwa inny skan: start zablokowany. */
  busy: boolean;
  /** Start na wybranych celach; po sukcesie zaznaczenie jest czyszczone. */
  onStart: (ids: string[]) => Promise<boolean>;
}

/** Wybór celów do jednego przebiegu: wyszukiwarka, 5 na stronę, „zaznacz wszystkie” w obrębie wyników. */
export function TargetPicker({ targets, busy, onStart }: TargetPickerProps) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [picked, setPicked] = useState<Set<string>>(new Set());

  const needle = query.trim().toLowerCase();
  const filtered = useMemo(
    () => (needle ? targets.filter((t) => `${t.value} ${t.kind}`.toLowerCase().includes(needle)) : targets),
    [targets, needle],
  );
  // usunięte cele wypadają z zaznaczenia; wykluczonych nie da się wybrać
  const selectable = useMemo(() => new Set(targets.filter((t) => !t.excluded).map((t) => t.id)), [targets]);
  const selected = [...picked].filter((id) => selectable.has(id));
  const filteredIds = filtered.filter((t) => !t.excluded).map((t) => t.id);
  const allOn = filteredIds.length > 0 && filteredIds.every((id) => picked.has(id));

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  const current = Math.min(page, pages - 1);
  const visible = filtered.slice(current * PAGE, current * PAGE + PAGE);

  const toggle = (id: string) =>
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const start = async () => {
    if (await onStart(selected)) setPicked(new Set());
  };

  return (
    <section className="panel mb-3 p-3" aria-labelledby="target-picker">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <h2 id="target-picker" className="text-[13px] font-semibold">
          Cele skanu
        </h2>
        <input
          type="search"
          className="min-w-0 flex-1 sm:max-w-64"
          aria-label="Szukaj celów"
          placeholder="szukaj: IP, CIDR, domena, typ"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setPage(0);
          }}
        />
        <button className={BTN_SECONDARY} disabled={filteredIds.length === 0} onClick={() => setPicked((prev) => toggleAll(prev, filteredIds))}>
          {allOn ? "Odznacz wszystkie" : "Zaznacz wszystkie"}
          {needle && ` (${filteredIds.length})`}
        </button>
        <span className="mono text-xs text-muted" role="status">
          zaznaczone: {selected.length}
        </span>
        <button className="ml-auto" disabled={busy || selected.length === 0} onClick={start} title="Przy ustawionych oknach czasowych start tylko w oknie">
          {busy ? "Skan w toku..." : `Uruchom skan (${selected.length})`}
        </button>
      </div>

      {filtered.length === 0 ? (
        <p className="my-2 text-muted">{needle ? "brak wyników" : "brak celów: dodaj je w Konfiguracja → Cele"}</p>
      ) : (
        <ul className="divide-y divide-line border-y border-line">
          {visible.map((t) => (
            <li key={t.id} className="flex min-w-0 items-center gap-2 px-1 py-1">
              <input
                type="checkbox"
                id={`pick-${t.id}`}
                aria-label={`Wybierz ${t.value}`}
                checked={!t.excluded && picked.has(t.id)}
                disabled={t.excluded}
                onChange={() => toggle(t.id)}
              />
              <label htmlFor={`pick-${t.id}`} className="mono min-w-0 flex-1 truncate" title={t.value}>
                {t.value}
              </label>
              <span className="shrink-0 text-xs text-muted">{t.kind}</span>
              {t.excluded && <span className="shrink-0 text-xs text-orange">wykluczony</span>}
            </li>
          ))}
        </ul>
      )}

      {pages > 1 && (
        <div className="mt-2 flex items-center gap-2">
          <button className={BTN_SECONDARY} disabled={current === 0} onClick={() => setPage(current - 1)}>
            Poprzednia
          </button>
          <span className="mono text-xs text-muted">
            {current + 1}/{pages}
          </span>
          <button className={BTN_SECONDARY} disabled={current >= pages - 1} onClick={() => setPage(current + 1)}>
            Następna
          </button>
          <span className="text-xs text-muted">wyników: {filtered.length}</span>
        </div>
      )}
    </section>
  );
}
