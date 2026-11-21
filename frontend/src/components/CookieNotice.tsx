// Informacja o jedynym ciasteczku aplikacji. Ciasteczko sesji jest niezbędne, więc nie wymaga zgody;
// komunikat tylko informuje i nie blokuje pracy. Zamknięcie zapamiętujemy w localStorage.
import { useEffect, useState } from "react";
import { api } from "../api";

const STORAGE_KEY = "asi.cookieNotice";

function wasDismissed(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

export function CookieNotice() {
  const [hidden, setHidden] = useState(wasDismissed);
  // czas sesji z backendu (ASI_SESSION_TTL_HOURS); przy błędzie tekst bez liczby godzin
  const [hours, setHours] = useState<number | null>(null);

  useEffect(() => {
    if (!hidden) {
      api.authConfig().then((c) => setHours(c.session_ttl_hours), () => setHours(null));
    }
  }, [hidden]);

  if (hidden) {
    return null;
  }

  const dismiss = () => {
    try {
      localStorage.setItem(STORAGE_KEY, "1");
    } catch {
      // storage niedostępny: komunikat zniknie do końca tej wizyty
    }
    setHidden(true);
  };

  return (
    <section
      role="region"
      aria-label="Informacja o ciasteczkach"
      className="fixed inset-x-0 bottom-0 z-50 flex flex-wrap items-center gap-3 border-t border-line bg-surface px-4 py-3 shadow-lg"
    >
      <p className="m-0 min-w-0 flex-1 basis-64 break-words">
        Ta aplikacja używa wyłącznie niezbędnego ciasteczka sesji <code>asi_session</code>, aby utrzymać
        zalogowanie ({hours ? `ważne do ${hours} godzin lub do wylogowania` : "do wylogowania lub wygaśnięcia sesji"}). Nie używamy ciasteczek
        analitycznych ani marketingowych.
      </p>
      <button type="button" onClick={dismiss}>
        Rozumiem
      </button>
    </section>
  );
}
