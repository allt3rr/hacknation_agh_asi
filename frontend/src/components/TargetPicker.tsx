import { useMemo, useState, type ReactNode } from "react";
import type { Target, VulnMode } from "../types";
import { BADGE, BTN_SECONDARY, toggleAll } from "../utils";
import { TagCombobox, collectTags } from "./TagCombobox";

const PAGE = 5;
const KIND_LABELS: Record<Target["kind"], string> = { ip: "IP", cidr: "CIDR", domain: "domena" };

interface TargetSelectProps {
  targets: Target[];
  value: ReadonlySet<string>;
  onChange: (next: Set<string>) => void;
  /** Unikalny prefiks id pól (dwie listy na jednej stronie). */
  idPrefix: string;
  /** Dodatkowe kontrolki w pasku narzędzi (np. start skanu). */
  actions?: ReactNode;
  heading?: ReactNode;
}

/** Zaznaczone cele, które nadal istnieją i nie są wykluczone. */
export function selectedTargets(targets: Target[], value: ReadonlySet<string>): string[] {
  return targets.filter((t) => !t.excluded && value.has(t.id)).map((t) => t.id);
}

/** Lista wyboru celów: wyszukiwarka, filtr tagu, 5 na stronę, „zaznacz wszystkie” w obrębie wyników. */
export function TargetSelect({ targets, value, onChange, idPrefix, actions, heading }: TargetSelectProps) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [tag, setTag] = useState<string | null>(null);
  const tags = useMemo(() => collectTags(targets), [targets]);

  const needle = query.trim().toLowerCase();
  const filtered = useMemo(
    () =>
      targets.filter(
        (t) => (!tag || t.tags.includes(tag)) && (!needle || `${t.value} ${t.kind} ${t.tags.join(" ")}`.toLowerCase().includes(needle)),
      ),
    [targets, needle, tag],
  );
  const selected = selectedTargets(targets, value);
  const filteredIds = filtered.filter((t) => !t.excluded).map((t) => t.id);
  const allOn = filteredIds.length > 0 && filteredIds.every((id) => value.has(id));

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  const current = Math.min(page, pages - 1);
  const visible = filtered.slice(current * PAGE, current * PAGE + PAGE);

  const toggle = (id: string) => {
    const next = new Set(value);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onChange(next);
  };

  return (
    <>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        {heading}
        <input
          type="search"
          className="min-w-0 flex-1 sm:max-w-64"
          aria-label="Szukaj celów"
          placeholder="szukaj: IP, CIDR, domena, typ, tag"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setPage(0);
          }}
        />
        <TagCombobox
          tags={tags}
          value={tag}
          onSelect={(next) => {
            setTag(next);
            setPage(0);
          }}
          label="Filtr celów: tag"
          placeholder="wszystkie tagi"
          clearLabel="wszystkie tagi"
        />
        <button type="button" className={BTN_SECONDARY} disabled={filteredIds.length === 0} onClick={() => onChange(toggleAll(value, filteredIds))}>
          {allOn ? "Odznacz wszystkie" : "Zaznacz wszystkie"}
          {(needle || tag) && ` (${filteredIds.length})`}
        </button>
        <span className="mono text-xs text-muted" role="status">
          zaznaczone: {selected.length}
        </span>
        {actions}
      </div>

      {filtered.length === 0 ? (
        <p className="my-2 text-muted">{needle || tag ? "brak wyników" : "brak celów: dodaj je w Konfiguracja → Cele"}</p>
      ) : (
        <ul className="divide-y divide-line border-y border-line">
          {visible.map((t) => (
            <li key={t.id} className="flex min-w-0 items-center gap-2 px-1 py-1">
              <input
                type="checkbox"
                id={`${idPrefix}-${t.id}`}
                aria-label={`Wybierz ${t.value}`}
                checked={!t.excluded && value.has(t.id)}
                disabled={t.excluded}
                onChange={() => toggle(t.id)}
              />
              <label htmlFor={`${idPrefix}-${t.id}`} className="mono min-w-0 flex-1 truncate" title={t.value}>
                {t.value}
              </label>
              <span className="w-16 shrink-0 text-xs text-muted" title="typ celu">
                {KIND_LABELS[t.kind] ?? t.kind}
              </span>
              <span className="flex max-w-[40%] min-w-0 shrink flex-wrap justify-end" aria-label="tagi">
                {t.tags.map((tagName) => (
                  <span key={tagName} className={BADGE}>
                    {tagName}
                  </span>
                ))}
              </span>
              {t.excluded && <span className="shrink-0 text-xs text-orange">wykluczony</span>}
            </li>
          ))}
        </ul>
      )}

      {pages > 1 && (
        <div className="mt-2 flex items-center gap-2">
          <button type="button" className={BTN_SECONDARY} disabled={current === 0} onClick={() => setPage(current - 1)}>
            Poprzednia
          </button>
          <span className="mono text-xs text-muted">
            {current + 1}/{pages}
          </span>
          <button type="button" className={BTN_SECONDARY} disabled={current >= pages - 1} onClick={() => setPage(current + 1)}>
            Następna
          </button>
          <span className="text-xs text-muted">wyników: {filtered.length}</span>
        </div>
      )}
    </>
  );
}

interface TargetPickerProps {
  targets: Target[];
  /** Trwa inny skan: start zablokowany. */
  busy: boolean;
  /** Start na wybranych celach; po sukcesie zaznaczenie jest czyszczone. */
  onStart: (ids: string[], vulnCheck: VulnMode) => Promise<boolean>;
}

/** Wybór celów do jednego przebiegu ręcznego. */
export function TargetPicker({ targets, busy, onStart }: TargetPickerProps) {
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [vulnCheck, setVulnCheck] = useState<VulnMode>("ask");
  const selected = selectedTargets(targets, picked);

  const start = async () => {
    if (await onStart(selected, vulnCheck)) setPicked(new Set());
  };

  return (
    <section className="panel mb-3 p-3" aria-labelledby="target-picker">
      <TargetSelect
        targets={targets}
        value={picked}
        onChange={setPicked}
        idPrefix="pick"
        heading={
          <h2 id="target-picker" className="text-[13px] font-semibold">
            Cele skanu
          </h2>
        }
        actions={
          <>
            <label className="ml-auto flex items-center gap-1 text-xs text-muted">
              Podatności po skanie
              <select value={vulnCheck} onChange={(e) => setVulnCheck(e.target.value as VulnMode)} aria-label="Sprawdzanie podatności po skanie">
                <option value="ask">zapytaj</option>
                <option value="auto">sprawdź automatycznie</option>
                <option value="off">nie sprawdzaj</option>
              </select>
            </label>
            <button disabled={busy || selected.length === 0} onClick={start}>
              {busy ? "Skan w toku..." : `Uruchom skan (${selected.length})`}
            </button>
          </>
        }
      />
    </section>
  );
}
