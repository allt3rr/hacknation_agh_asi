import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { Schedule, ScheduleWindow, Session } from "../types";
import { BTN_SECONDARY } from "../utils";

const DAYS: [string, string][] = [
  ["mon", "pn"],
  ["tue", "wt"],
  ["wed", "śr"],
  ["thu", "cz"],
  ["fri", "pt"],
  ["sat", "sb"],
  ["sun", "nd"],
];

/** Harmonogram automatycznych skanów: okna czasowe uruchomienia i częstotliwość (treść zadania, pkt 2 i sekcja 3). */
export function SchedulePage({ session }: { session: Session }) {
  const { data, error, reload } = useApiData(api.schedule.get);
  const { info, run } = useNotice();
  const [draft, setDraft] = useState<Schedule | null>(null);
  const editable = can(session, "scans.configure");

  useEffect(() => {
    if (data) setDraft(structuredClone(data));
  }, [data]);

  if (error) {
    return (
      <p role="alert" className="my-3.5 text-red">
        {error}
      </p>
    );
  }
  if (!draft) {
    return (
      <p role="status" className="my-3.5 text-muted">
        Ładowanie...
      </p>
    );
  }

  const update = (patch: Partial<Schedule>) => setDraft({ ...draft, ...patch });
  const setWindow = (index: number, patch: Partial<ScheduleWindow>) =>
    update({ windows: draft.windows.map((w, i) => (i === index ? { ...w, ...patch } : w)) });
  const toggleDay = (index: number, day: string) => {
    const days = draft.windows[index].days;
    setWindow(index, { days: days.includes(day) ? days.filter((d) => d !== day) : [...days, day] });
  };

  const save = (event: FormEvent) => {
    event.preventDefault();
    run(async () => {
      await api.schedule.save(draft);
      info("Zapisano harmonogram. Backend sprawdza go co 60 s.");
      await reload();
    });
  };

  return (
    <form onSubmit={save}>
      {!editable && <p className="mb-2 text-muted">tylko odczyt (brak scans.configure)</p>}

      <fieldset disabled={!editable} className="contents">
        <Card title="Automatyczne skany">
          <div className="my-2 flex flex-wrap items-center gap-2">
            <input id="schedule-enabled" type="checkbox" checked={draft.enabled} onChange={(e) => update({ enabled: e.target.checked })} />
            <label htmlFor="schedule-enabled">Włącz automatyczne skany</label>
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
              value={draft.every_hours}
              onChange={(e) => update({ every_hours: Number(e.target.value) })}
            />
            <span>godz.</span>
            <span id="every-hours-hint" className="text-xs text-muted" title="Po skanie częściowym lub błędnym kolejny startuje bez czekania.">
              od startu poprzedniego, 1–720
            </span>
          </div>
        </Card>

        <Card title="Okna czasowe uruchomienia">
          <p
            className="mb-2 text-xs text-muted"
            title="Dotyczy też startu ręcznego. Skan niedokończony w oknie jest zatrzymywany, reszta adresów idzie na początek kolejnego okna. Okno może przechodzić przez północ (22:00–06:00)."
          >
            UTC (PL: zimą +1, latem +2) · start tylko w oknie · reszta przechodzi do następnego okna
          </p>
          {draft.windows.length === 0 && <p className="mb-2 text-muted">brak okien: start o dowolnej porze</p>}
          {draft.windows.map((window, index) => (
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
                onClick={() => update({ windows: draft.windows.filter((_, i) => i !== index) })}
              >
                Usuń
              </button>
            </fieldset>
          ))}
          <button type="button" className={BTN_SECONDARY} onClick={() => update({ windows: [...draft.windows, { start: "22:00", end: "06:00", days: [] }] })}>
            Dodaj okno
          </button>
        </Card>

        {editable && (
          <div className="flex flex-wrap gap-2">
            <button type="submit">Zapisz harmonogram</button>
            <button type="button" className={BTN_SECONDARY} onClick={() => data && setDraft(structuredClone(data))}>
              Cofnij zmiany
            </button>
          </div>
        )}
      </fieldset>
      <p className="mt-3 text-xs text-muted">
        pps, porty, równoległość nmap: <code>backend/config/scan.toml</code>
      </p>
    </form>
  );
}
