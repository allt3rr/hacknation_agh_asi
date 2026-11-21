import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { useApiData, useNotice } from "../hooks";
import { can } from "../permissions";
import type { Role, ScheduleWindow, Settings } from "../types";
import { BTN_SECONDARY } from "../utils";

const DAYS: [string, string][] = [
  ["mon", "pon"],
  ["tue", "wt"],
  ["wed", "śr"],
  ["thu", "czw"],
  ["fri", "pt"],
  ["sat", "sob"],
  ["sun", "niedz"],
];

/** Konfiguracja skanu: okna czasowe, częstotliwość i tempo (wymaganie "konfiguracja skanu" i "ograniczanie tempa"). */
export function SettingsPage({ role }: { role: Role }) {
  const { data, error, reload } = useApiData(api.settings.get);
  const { info, run } = useNotice();
  const [draft, setDraft] = useState<Settings | null>(null);
  const editable = can(role, "scan");

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

  const setSchedule = (patch: Partial<Settings["schedule"]>) => setDraft({ ...draft, schedule: { ...draft.schedule, ...patch } });
  const setWindow = (index: number, patch: Partial<ScheduleWindow>) =>
    setSchedule({ windows: draft.schedule.windows.map((w, i) => (i === index ? { ...w, ...patch } : w)) });
  const toggleDay = (index: number, day: string) => {
    const days = draft.schedule.windows[index].days;
    setWindow(index, { days: days.includes(day) ? days.filter((d) => d !== day) : [...days, day] });
  };
  const setNumber = (key: "global_max_rate" | "concurrency" | "http_concurrency", value: string) =>
    setDraft({ ...draft, [key]: Number(value) });

  const save = (event: FormEvent) => {
    event.preventDefault();
    run(async () => {
      await api.settings.save(draft);
      info("Zapisano ustawienia. Obowiązują od następnego skanu, harmonogram uwzględni je w ciągu minuty.");
      await reload();
    });
  };

  return (
    <form onSubmit={save}>
      {!editable && <p className="mb-3 text-muted">Twoja rola pozwala tylko na podgląd ustawień.</p>}

      <fieldset disabled={!editable} className="contents">
        <Card title="Harmonogram skanów">
          <div className="my-2 flex flex-wrap items-center gap-2">
            <input
              id="schedule-enabled"
              type="checkbox"
              checked={draft.schedule.enabled}
              onChange={(e) => setSchedule({ enabled: e.target.checked })}
            />
            <label htmlFor="schedule-enabled">Cykliczne skany włączone</label>
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
              value={draft.schedule.every_hours}
              onChange={(e) => setSchedule({ every_hours: Number(e.target.value) })}
            />
            <span>godz.</span>
          </div>

          <h3 className="mt-4 font-semibold">Okna czasowe</h3>
          <p className="mb-2 text-muted">
            Skan rusza tylko w oknie. Jeśli nie zmieści się w oknie, jest zatrzymywany, a niezeskanowane adresy idą na początek kolejki w następnym oknie. Brak okien = dowolna pora. Czas lokalny serwera.
          </p>
          {draft.schedule.windows.map((window, index) => (
            <fieldset key={index} className="my-2 flex flex-wrap items-center gap-2 rounded-md border border-line p-2">
              <legend className="px-1 text-muted">Okno {index + 1}</legend>
              <label htmlFor={`win-start-${index}`}>od</label>
              <input id={`win-start-${index}`} type="time" required value={window.start} onChange={(e) => setWindow(index, { start: e.target.value })} />
              <label htmlFor={`win-end-${index}`}>do</label>
              <input id={`win-end-${index}`} type="time" required value={window.end} onChange={(e) => setWindow(index, { end: e.target.value })} />
              <span className="text-muted">dni (puste = codziennie):</span>
              {DAYS.map(([day, label]) => (
                <label key={day} className="inline-flex items-center gap-1">
                  <input type="checkbox" checked={window.days.includes(day)} onChange={() => toggleDay(index, day)} />
                  {label}
                </label>
              ))}
              <button
                type="button"
                className={BTN_SECONDARY}
                aria-label={`Usuń okno ${index + 1}`}
                onClick={() => setSchedule({ windows: draft.schedule.windows.filter((_, i) => i !== index) })}
              >
                Usuń
              </button>
            </fieldset>
          ))}
          <button
            type="button"
            className={BTN_SECONDARY}
            onClick={() => setSchedule({ windows: [...draft.schedule.windows, { start: "22:00", end: "06:00", days: [] }] })}
          >
            Dodaj okno
          </button>
        </Card>

        <Card title="Tempo skanowania">
          <p className="mb-2 text-muted">Ograniczenie intensywności chroni skanowaną infrastrukturę. Limit pakietów jest dzielony równo między procesy nmap.</p>
          <div className="grid gap-2 sm:grid-cols-[max-content_8rem] sm:items-center">
            <label htmlFor="max-rate">Łączny limit pakietów/s</label>
            <input id="max-rate" type="number" min={1} max={100000} required value={draft.global_max_rate} onChange={(e) => setNumber("global_max_rate", e.target.value)} />
            <label htmlFor="concurrency">Równoległe procesy nmap (podgrupy)</label>
            <input id="concurrency" type="number" min={1} max={64} required value={draft.concurrency} onChange={(e) => setNumber("concurrency", e.target.value)} />
            <label htmlFor="http-concurrency">Równoległe zapytania HTTP</label>
            <input id="http-concurrency" type="number" min={1} max={256} required value={draft.http_concurrency} onChange={(e) => setNumber("http_concurrency", e.target.value)} />
          </div>
          <p className="mt-2 text-muted">
            Na proces nmap: ok. {Math.max(1, Math.floor(draft.global_max_rate / Math.max(1, draft.concurrency)))} pakietów/s.
          </p>
        </Card>

        {editable && (
          <div className="flex flex-wrap gap-2">
            <button type="submit">Zapisz ustawienia</button>
            <button type="button" className={BTN_SECONDARY} onClick={() => data && setDraft(structuredClone(data))}>
              Cofnij zmiany
            </button>
          </div>
        )}
      </fieldset>
    </form>
  );
}
