import { useRef, useState, type FormEvent, type RefObject } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { TargetSelect, selectedTargets } from "../components/TargetPicker";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { ScheduleEntry, ScheduleInput, ScheduleWindow, Session, Target, VulnMode } from "../types";
import { BTN_SECONDARY, formatWindows, nextScheduledStart } from "../utils";

const DAYS: [string, string][] = [
  ["mon", "pn"],
  ["tue", "wt"],
  ["wed", "śr"],
  ["thu", "cz"],
  ["fri", "pt"],
  ["sat", "sb"],
  ["sun", "nd"],
];

const EMPTY: ScheduleInput = { name: "", enabled: true, every_hours: 24, windows: [], target_ids: [], vuln_check: "ask" };

interface Draft {
  /** brak = nowa pozycja */
  id?: string;
  value: ScheduleInput;
  picked: Set<string>;
}

/** Harmonogram automatycznych skanów: pozycje z celami, częstotliwością i oknami czasowymi (treść zadania, pkt 2). */
export function SchedulePage({ session }: { session: Session }) {
  const { data: entries, error, reload } = useApiData(api.schedules.list);
  const { data: targets } = useApiData(api.targets.list);
  const { info, run } = useNotice();
  const [draft, setDraft] = useState<Draft | null>(null);
  const formHeading = useRef<HTMLHeadingElement>(null);
  const editable = can(session, "scans.configure");

  if (error) {
    return (
      <p role="alert" className="my-3.5 text-red">
        {error}
      </p>
    );
  }
  if (!entries) {
    return (
      <p role="status" className="my-3.5 text-muted">
        Ładowanie...
      </p>
    );
  }

  const open = (entry?: ScheduleEntry) => {
    // tylko pola zapisu: backend odrzuca nieznane pola (id, last_run_at…)
    const value: ScheduleInput = entry
      ? { name: entry.name, enabled: entry.enabled, every_hours: entry.every_hours, windows: structuredClone(entry.windows), target_ids: entry.target_ids, vuln_check: entry.vuln_check }
      : structuredClone(EMPTY);
    setDraft({ id: entry?.id, value, picked: new Set(value.target_ids) });
    requestAnimationFrame(() => {
      formHeading.current?.scrollIntoView({ block: "start" });
      formHeading.current?.focus();
    });
  };

  const remove = (entry: ScheduleEntry) =>
    run(async () => {
      if (!confirm(`Usunąć pozycję harmonogramu „${entry.name}”? Przebiegi zostaną zachowane.`)) return;
      await api.schedules.remove(entry.id);
      if (draft?.id === entry.id) setDraft(null);
      info(`Usunięto pozycję „${entry.name}”`);
      await reload();
    });

  return (
    <>
      <Card
        title={`Pozycje harmonogramu (${entries.length})`}
        actions={
          editable && (
            <button type="button" onClick={() => open()}>
              Dodaj pozycję
            </button>
          )
        }
      >
        {!editable && <p className="mb-2 text-muted">tylko odczyt (brak scans.configure)</p>}
        <p className="mb-2 text-xs text-muted" title="Backend sprawdza pozycje co 60 s; naraz trwa najwyżej jeden skan.">
          okna w UTC (PL: zimą +1, latem +2) · start pozycji tylko w jej oknie · start ręczny bez ograniczeń
        </p>
        <DataTable
          label="Pozycje harmonogramu"
          rows={entries}
          rowKey={(s) => s.id}
          emptyText="Brak pozycji harmonogramu"
          columns={[
            { header: "Nazwa", render: (s) => s.name },
            {
              header: "Cele",
              mono: true,
              render: (s) => (
                <>
                  {s.target_ids.length - s.missing_targets}
                  {s.missing_targets > 0 && (
                    <span className="ml-1 text-orange" title="Część celów usunięto w Konfiguracja → Cele">
                      ({s.missing_targets} usunięte)
                    </span>
                  )}
                </>
              ),
            },
            { header: "Częstotliwość", render: (s) => `co ${s.every_hours} h` },
            { header: "Okna", render: (s) => formatWindows(s.windows) },
            { header: "Stan", render: (s) => (s.enabled ? <span className="text-green">włączona</span> : <span className="text-muted">wyłączona</span>) },
            { header: "Następny start", render: (s) => nextScheduledStart(s) },
            ...(editable
              ? [
                  {
                    header: "",
                    render: (s: ScheduleEntry) => (
                      <div className="flex gap-1">
                        <button type="button" className={BTN_SECONDARY} aria-label={`Edytuj pozycję ${s.name}`} onClick={() => open(s)}>
                          Edytuj
                        </button>
                        <button type="button" className={BTN_SECONDARY} aria-label={`Usuń pozycję ${s.name}`} onClick={() => remove(s)}>
                          Usuń
                        </button>
                      </div>
                    ),
                  },
                ]
              : []),
          ]}
        />
      </Card>

      {editable && draft && (
        <ScheduleForm
          draft={draft}
          setDraft={setDraft}
          targets={targets ?? []}
          headingRef={formHeading}
          onSave={(value) =>
            run(async () => {
              if (draft.id) await api.schedules.update(draft.id, value);
              else await api.schedules.create(value);
              info(`Zapisano pozycję „${value.name}”. Backend sprawdza harmonogram co 60 s.`);
              setDraft(null);
              await reload();
            })
          }
        />
      )}
      <p className="mt-3 text-xs text-muted">
        pps, porty, równoległość nmap: <code>backend/config/scan.toml</code>
      </p>
    </>
  );
}

interface ScheduleFormProps {
  draft: Draft;
  setDraft: (d: Draft | null) => void;
  targets: Target[];
  headingRef: RefObject<HTMLHeadingElement>;
  onSave: (value: ScheduleInput) => void;
}

function ScheduleForm({ draft, setDraft, targets, headingRef, onSave }: ScheduleFormProps) {
  const d = draft.value;
  const update = (patch: Partial<ScheduleInput>) => setDraft({ ...draft, value: { ...d, ...patch } });
  const setWindow = (index: number, patch: Partial<ScheduleWindow>) => update({ windows: d.windows.map((w, i) => (i === index ? { ...w, ...patch } : w)) });
  const toggleDay = (index: number, day: string) => {
    const days = d.windows[index].days;
    setWindow(index, { days: days.includes(day) ? days.filter((x) => x !== day) : [...days, day] });
  };
  const ids = selectedTargets(targets, draft.picked);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    onSave({ ...d, name: d.name.trim(), target_ids: ids });
  };

  return (
    <form onSubmit={submit}>
      <Card title={draft.id ? `Edycja pozycji „${d.name}”` : "Nowa pozycja harmonogramu"} headingRef={headingRef}>
        <div className="my-2 flex flex-wrap items-center gap-2">
          <label htmlFor="schedule-name">Nazwa</label>
          <input id="schedule-name" required maxLength={100} className="min-w-0 flex-1 sm:max-w-80" value={d.name} onChange={(e) => update({ name: e.target.value })} />
          <input id="schedule-enabled" type="checkbox" checked={d.enabled} onChange={(e) => update({ enabled: e.target.checked })} />
          <label htmlFor="schedule-enabled">Włączona</label>
        </div>
        <div className="my-2 flex flex-wrap items-center gap-2">
          <label htmlFor="every-hours">Częstotliwość: co</label>
          <input
            id="every-hours"
            type="number"
            min={1}
            max={720}
            required
            className="w-20"
            aria-describedby="every-hours-hint"
            value={d.every_hours}
            onChange={(e) => update({ every_hours: Number(e.target.value) })}
          />
          <span>godz.</span>
          <span id="every-hours-hint" className="text-xs text-muted" title="Po skanie częściowym lub błędnym kolejny startuje bez czekania.">
            od startu poprzedniego przebiegu tej pozycji, 1–720
          </span>
          <label className="ml-auto flex items-center gap-1 text-xs text-muted">
            Podatności po skanie
            <select value={d.vuln_check} onChange={(e) => update({ vuln_check: e.target.value as VulnMode })} aria-label="Sprawdzanie podatności po skanie">
              <option value="ask">zapytaj</option>
              <option value="auto">sprawdź automatycznie</option>
              <option value="off">nie sprawdzaj</option>
            </select>
          </label>
        </div>

        <fieldset className="my-2 rounded-xl border border-line p-3">
          <legend className="px-1 text-muted">Cele</legend>
          <TargetSelect targets={targets} value={draft.picked} onChange={(picked) => setDraft({ ...draft, picked })} idPrefix="schedule-target" />
        </fieldset>

        <fieldset className="my-2 rounded-xl border border-line p-3">
          <legend className="px-1 text-muted">Okna czasowe uruchomienia</legend>
          <p
            className="mb-2 text-xs text-muted"
            title="Skan niedokończony w oknie jest zatrzymywany, reszta adresów idzie na początek kolejnego okna. Okno może przechodzić przez północ (22:00–06:00)."
          >
            UTC · start tylko w oknie · reszta przechodzi do następnego okna
          </p>
          {d.windows.length === 0 && <p className="mb-2 text-muted">brak okien: start o dowolnej porze</p>}
          {d.windows.map((window, index) => (
            <fieldset key={index} className="my-2 flex flex-wrap items-center gap-2 rounded-xl border border-line p-3">
              <legend className="px-1 text-muted">Okno {index + 1}</legend>
              <label htmlFor={`win-start-${index}`}>od</label>
              <input id={`win-start-${index}`} type="time" required value={window.start} onChange={(e) => setWindow(index, { start: e.target.value })} />
              <label htmlFor={`win-end-${index}`}>do</label>
              <input id={`win-end-${index}`} type="time" required value={window.end} onChange={(e) => setWindow(index, { end: e.target.value })} />
              <span className="text-muted">dni tygodnia (bez zaznaczenia: każdy dzień):</span>
              {DAYS.map(([day, short]) => (
                <label key={day} className="inline-flex items-center gap-1">
                  <input type="checkbox" checked={window.days.includes(day)} onChange={() => toggleDay(index, day)} />
                  {short}
                </label>
              ))}
              <button
                type="button"
                className={BTN_SECONDARY}
                aria-label={`Usuń okno ${index + 1}`}
                onClick={() => update({ windows: d.windows.filter((_, i) => i !== index) })}
              >
                Usuń
              </button>
            </fieldset>
          ))}
          <button type="button" className={BTN_SECONDARY} onClick={() => update({ windows: [...d.windows, { start: "22:00", end: "06:00", days: [] }] })}>
            Dodaj okno
          </button>
        </fieldset>

        <div className="flex flex-wrap items-center gap-2">
          <button type="submit" disabled={ids.length === 0}>
            Zapisz pozycję ({ids.length} {ids.length === 1 ? "cel" : "celów"})
          </button>
          <button type="button" className={BTN_SECONDARY} onClick={() => setDraft(null)}>
            Anuluj
          </button>
          {ids.length === 0 && <span className="text-xs text-muted">zaznacz co najmniej jeden cel</span>}
        </div>
      </Card>
    </form>
  );
}
