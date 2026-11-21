import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { INTEREST_HINT, interestLabel, interestScore } from "../interest";
import type { Annotation, Detection, Observation } from "../types";
import { BTN_SECONDARY, errorMessage } from "../utils";
import { DataTable, type Column } from "./DataTable";

const SEVERITIES = ["", "info", "low", "medium", "high", "critical"];

const SEVERITY_LABELS: Record<string, string> = {
  "": "brak",
  info: "informacyjny",
  low: "niski",
  medium: "średni",
  high: "wysoki",
  critical: "krytyczny",
};

const BADGE = "mr-1 my-px inline-block rounded-full border border-line bg-bg px-2 py-px text-xs";

const keyOf = (o: Observation) => `${o.ip}:${o.port}/${o.proto}`;

function DetectionBadge({ detection }: { detection: Detection }) {
  const version = detection.version ? ` ${detection.version}` : "";
  return (
    <span className={BADGE}>
      {detection.name}
      {version} ({detection.confidence}%)
    </span>
  );
}

interface ObservationTableProps {
  observations: Observation[];
  /** Adnotacje analityków według klucza ip:port/proto. */
  annotations?: Map<string, Annotation>;
  /** Gdy podane, w szczegółach usługi pojawia się formularz edycji adnotacji. */
  onSaveAnnotation?: (annotation: Annotation) => Promise<void>;
  /** Gdy podane, usługi można zaznaczać i wysłać wybrane do DefectDojo. */
  onSendToDefectDojo?: (keys: string[]) => Promise<void>;
}

interface ServiceGroup {
  name: string;
  members: Observation[];
  technologies: string[];
  topScore: number;
}

/** Grupowanie podobnych usług: ten sam serwis, produkt i wersja. */
function groupServices(observations: Observation[], score: (o: Observation) => number): ServiceGroup[] {
  const groups = new Map<string, ServiceGroup>();
  for (const o of observations) {
    const name = [o.service, o.product, o.version].filter(Boolean).join(" ") || "nieznana usługa";
    const group = groups.get(name) ?? { name, members: [], technologies: [], topScore: 0 };
    group.members.push(o);
    for (const d of o.detections) {
      if (!group.technologies.includes(d.name)) group.technologies.push(d.name);
    }
    group.topScore = Math.max(group.topScore, score(o));
    groups.set(name, group);
  }
  return [...groups.values()].sort((a, b) => b.members.length - a.members.length);
}

export function ObservationTable({ observations, annotations, onSaveAnnotation, onSendToDefectDojo }: ObservationTableProps) {
  const [selected, setSelected] = useState<Observation | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [grouped, setGrouped] = useState(false);
  const [sending, setSending] = useState(false);

  const score = (o: Observation) => interestScore(o, annotations?.get(keyOf(o)));
  // Najciekawsze usługi na górze.
  const sorted = useMemo(
    () => [...observations].sort((a, b) => interestScore(b, annotations?.get(keyOf(b))) - interestScore(a, annotations?.get(keyOf(a)))),
    [observations, annotations],
  );

  const toggle = (key: string) => {
    const next = new Set(checked);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setChecked(next);
  };

  const send = async () => {
    if (!onSendToDefectDojo) return;
    setSending(true);
    try {
      await onSendToDefectDojo([...checked]);
      setChecked(new Set());
    } finally {
      setSending(false);
    }
  };

  const columns: Column<Observation>[] = [
    ...(onSendToDefectDojo
      ? [
          {
            header: "Wybór",
            render: (o: Observation) => (
              <input type="checkbox" aria-label={`Zaznacz usługę ${keyOf(o)}`} checked={checked.has(keyOf(o))} onChange={() => toggle(keyOf(o))} />
            ),
          },
        ]
      : []),
    {
      header: "Usługa",
      render: (o) => (
        <>
          {keyOf(o)}
          {o.hostname && <div className="text-muted">{o.hostname}</div>}
        </>
      ),
    },
    {
      header: "Ocena",
      render: (o) => {
        const value = score(o);
        return (
          <span className={value >= 60 ? "font-semibold text-red" : value >= 30 ? "font-medium text-orange" : "text-muted"}>
            {value} ({interestLabel(value)})
          </span>
        );
      },
    },
    { header: "Serwis", render: (o) => [o.service, o.product, o.version].filter(Boolean).join(" ") },
    { header: "HTTP", render: (o) => o.http?.status ?? "" },
    { header: "Tytuł", render: (o) => o.http?.title ?? "" },
    { header: "Technologie", render: (o) => o.detections.map((d) => <DetectionBadge key={d.signature_id} detection={d} />) },
    { header: "Adnotacja", render: (o) => <AnnotationSummary annotation={annotations?.get(keyOf(o))} /> },
    {
      header: "",
      render: (o) => (
        <button className={BTN_SECONDARY} aria-label={`Szczegóły usługi ${keyOf(o)}`} onClick={() => setSelected(o)}>
          Szczegóły
        </button>
      ),
    },
  ];

  return (
    <>
      <div className="my-2 flex flex-wrap items-center gap-2">
        <label className="inline-flex items-center gap-1">
          <input type="checkbox" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />
          Grupuj podobne usługi
        </label>
        <span className="text-muted" title={INTEREST_HINT}>
          Sortowanie wg oceny priorytetu (najciekawsze na górze).
        </span>
        {onSendToDefectDojo && !grouped && (
          <>
            <span className="flex-1" />
            <button className={BTN_SECONDARY} onClick={() => setChecked(new Set(observations.map(keyOf)))}>
              Zaznacz wszystkie
            </button>
            {checked.size > 0 && (
              <button className={BTN_SECONDARY} onClick={() => setChecked(new Set())}>
                Wyczyść zaznaczenie
              </button>
            )}
            <button onClick={send} disabled={checked.size === 0 || sending} aria-busy={sending}>
              {sending ? "Wysyłanie..." : `Wyślij zaznaczone (${checked.size}) do DefectDojo`}
            </button>
          </>
        )}
      </div>

      {grouped ? (
        <DataTable
          label="Grupy podobnych usług"
          rows={groupServices(sorted, score)}
          rowKey={(g) => g.name}
          filterBy={(g) => [g.name, ...g.technologies].join(" ")}
          columns={[
            { header: "Usługa", render: (g) => g.name },
            { header: "Liczba", render: (g) => g.members.length },
            { header: "Technologie", render: (g) => g.technologies.join(", ") },
            { header: "Najwyższa ocena", render: (g) => `${g.topScore} (${interestLabel(g.topScore)})` },
            {
              header: "Przykłady",
              render: (g) => g.members.slice(0, 5).map(keyOf).join(", ") + (g.members.length > 5 ? ` i ${g.members.length - 5} więcej` : ""),
            },
          ]}
        />
      ) : (
        <DataTable
          columns={columns}
          rows={sorted}
          rowKey={keyOf}
          emptyText="Brak usług"
          label="Usługi"
          filterBy={(o) =>
            [keyOf(o), o.hostname, o.service, o.product, o.version, o.http?.title, ...o.detections.map((d) => d.name), ...(annotations?.get(keyOf(o))?.tags ?? [])].join(" ")
          }
        />
      )}
      {selected && (
        <ObservationDetails
          key={keyOf(selected)}
          observation={selected}
          annotation={annotations?.get(keyOf(selected))}
          onSaveAnnotation={onSaveAnnotation}
          onClose={() => setSelected(null)}
        />
      )}
    </>
  );
}

function AnnotationSummary({ annotation }: { annotation?: Annotation }) {
  if (!annotation) return null;
  return (
    <>
      {annotation.severity && <span className={`${BADGE} font-medium`}>priorytet: {SEVERITY_LABELS[annotation.severity] ?? annotation.severity}</span>}
      {annotation.tags.map((tag) => (
        <span key={tag} className={BADGE}>
          #{tag}
        </span>
      ))}
      {annotation.note && <div className="text-muted">{annotation.note}</div>}
    </>
  );
}

interface DetailsProps {
  observation: Observation;
  annotation?: Annotation;
  onSaveAnnotation?: (annotation: Annotation) => Promise<void>;
  onClose: () => void;
}

function ObservationDetails({ observation: o, annotation, onSaveAnnotation, onClose }: DetailsProps) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const http = o.http;

  useEffect(() => {
    headingRef.current?.focus();
    headingRef.current?.scrollIntoView({ block: "start" });
  }, []);

  return (
    <section className="mt-3 rounded-[10px] border border-line bg-bg p-3" aria-labelledby="observation-details">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h3 id="observation-details" ref={headingRef} tabIndex={-1} className="font-bold outline-none">
          Szczegóły: {keyOf(o)}
        </h3>
        <button className={BTN_SECONDARY} onClick={onClose}>
          Zamknij szczegóły
        </button>
      </div>

      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 [&_dt]:text-muted [&_dd]:break-all">
        <dt>Host</dt>
        <dd>{o.hostname ?? o.ip}</dd>
        <dt>Stan</dt>
        <dd>{o.state}</dd>
        <dt>Serwis</dt>
        <dd>{[o.service, o.product, o.version].filter(Boolean).join(" ") || "—"}</dd>
        {http && (
          <>
            <dt>URL</dt>
            <dd>{http.url}</dd>
            {http.final_url && http.final_url !== http.url && (
              <>
                <dt>URL końcowy</dt>
                <dd>{http.final_url}</dd>
              </>
            )}
            <dt>Kod HTTP</dt>
            <dd>{http.status}</dd>
            <dt>Tytuł strony</dt>
            <dd>{http.title ?? "—"}</dd>
            <dt>Przekierowania</dt>
            <dd>{http.redirects.length ? http.redirects.join(" → ") : "brak"}</dd>
            <dt>Certyfikat TLS</dt>
            <dd>
              {http.tls ? (
                <>
                  podmiot: {http.tls.subject}
                  <br />
                  wystawca: {http.tls.issuer}
                  <br />
                  ważny: {http.tls.not_before} – {http.tls.not_after}
                  <br />
                  <span className="text-muted">SHA-256: {http.tls.sha256}</span>
                </>
              ) : (
                "brak"
              )}
            </dd>
          </>
        )}
      </dl>

      {o.detections.length > 0 && (
        <>
          <h4 className="mt-3 font-semibold">Wykryte technologie i dowody</h4>
          <ul className="list-disc pl-5">
            {o.detections.map((d) => (
              <li key={d.signature_id}>
                {d.name}
                {d.version ? ` ${d.version}` : ""} [{d.category}], pewność {d.confidence}%
                {d.evidence.length > 0 && <span className="text-muted">: {d.evidence.join("; ")}</span>}
              </li>
            ))}
          </ul>
        </>
      )}

      {http && (
        <>
          <h4 className="mt-3 font-semibold">Nagłówki ({Object.keys(http.headers).length})</h4>
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 font-mono text-xs [&_dd]:break-all">
            {Object.entries(http.headers).map(([name, value]) => (
              <div key={name} className="contents">
                <dt className="text-muted">{name}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
          <h4 className="mt-3 font-semibold">Ciasteczka ({http.cookies.length})</h4>
          {http.cookies.length ? (
            <ul className="list-disc pl-5 font-mono text-xs break-all">
              {http.cookies.map((cookie, i) => (
                <li key={i}>{cookie}</li>
              ))}
            </ul>
          ) : (
            <p className="text-muted">brak</p>
          )}
        </>
      )}

      {onSaveAnnotation ? (
        <AnnotationForm annotationKey={keyOf(o)} annotation={annotation} onSave={onSaveAnnotation} />
      ) : (
        annotation && (
          <>
            <h4 className="mt-3 font-semibold">Adnotacja</h4>
            <AnnotationSummary annotation={annotation} />
          </>
        )
      )}
    </section>
  );
}

interface AnnotationFormProps {
  annotationKey: string;
  annotation?: Annotation;
  onSave: (annotation: Annotation) => Promise<void>;
}

/** Edycja znaleziska: tagi, priorytet, notatka. Zapis trafia do adnotacji, więc przetrwa kolejne skany. */
function AnnotationForm({ annotationKey, annotation, onSave }: AnnotationFormProps) {
  const [tags, setTags] = useState(annotation?.tags.join(", ") ?? "");
  const [severity, setSeverity] = useState(annotation?.severity ?? "");
  const [note, setNote] = useState(annotation?.note ?? "");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await onSave({
        key: annotationKey,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
        severity: severity || null,
        note: note.trim() || null,
      });
      toast.success(`Zapisano adnotację dla ${annotationKey}`);
    } catch (e) {
      toast.error(errorMessage(e), { duration: 10_000 });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="mt-3" onSubmit={handleSubmit}>
      <h4 className="font-semibold">Edycja znaleziska (zachowywana przy kolejnych skanach)</h4>
      <div className="my-2 grid gap-2 sm:grid-cols-[max-content_1fr] sm:items-center">
        <label htmlFor="ann-tags">Tagi (po przecinku)</label>
        <input id="ann-tags" value={tags} onChange={(e) => setTags(e.target.value)} />
        <label htmlFor="ann-severity">Priorytet analityczny</label>
        <select id="ann-severity" className="justify-self-start" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABELS[s]}
            </option>
          ))}
        </select>
        <label htmlFor="ann-note">Notatka</label>
        <textarea id="ann-note" rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
      <button type="submit" disabled={busy} aria-busy={busy}>
        {busy ? "Zapisywanie..." : "Zapisz adnotację"}
      </button>
    </form>
  );
}
