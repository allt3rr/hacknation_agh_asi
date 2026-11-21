import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api";
import { IconActivity, IconRadar, IconShield, IconTarget } from "../components/icons";
import type { Session } from "../types";
import { errorMessage } from "../utils";

interface LoginPageProps {
  onLogin: (session: Session) => void;
}

const FEATURES = [
  { icon: <IconTarget className="size-4" />, text: "Wykrywanie aktywnych hostów i wystawionych usług" },
  { icon: <IconShield className="size-4" />, text: "Technologie webowe, CMS-y, charakterystyczne nagłówki i ciasteczka" },
  { icon: <IconActivity className="size-4" />, text: "Rejestrowanie zmian widocznych w czasie" },
];

/** Animowany radar (dekoracja): przemiatająca wiązka i punkty wykrytych hostów. */
function Radar() {
  return (
    <svg viewBox="0 0 200 200" className="size-56 text-accent-2 xl:size-64" aria-hidden="true">
      <defs>
        <linearGradient id="sweep" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="currentColor" stopOpacity="0" />
          <stop offset="1" stopColor="currentColor" stopOpacity="0.45" />
        </linearGradient>
      </defs>
      {[90, 65, 40, 15].map((r) => (
        <circle key={r} cx="100" cy="100" r={r} fill="none" stroke="currentColor" strokeOpacity="0.25" />
      ))}
      <path d="M100 10v180M10 100h180" stroke="currentColor" strokeOpacity="0.15" />
      <g className="animate-sweep">
        <path d="M100 100 L190 100 A90 90 0 0 0 163.6 36.4 Z" fill="url(#sweep)" />
      </g>
      {[
        [138, 62],
        [62, 128],
        [150, 140],
        [84, 54],
      ].map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r="3.5" fill="currentColor" className="animate-pulse-dot" style={{ animationDelay: `${i * 0.4}s` }} />
      ))}
    </svg>
  );
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      onLogin(await api.login(username, password));
    } catch (e) {
      setError(e instanceof ApiError && e.status === 401 ? "Nieprawidłowy login lub hasło" : errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-screen lg:grid-cols-[1.1fr_1fr]">
      <section aria-label="O aplikacji" className="relative hidden flex-col justify-between overflow-hidden p-10 lg:flex">
        <div className="flex items-center gap-3">
          <span className="brand-gradient grid size-10 place-items-center rounded-xl text-white shadow-[0_8px_24px_-8px_var(--glow)]">
            <IconRadar className="size-6" />
          </span>
          <span className="text-lg font-semibold">ASI</span>
        </div>
        <div className="animate-rise">
          <Radar />
          <p className="mt-6 text-4xl leading-tight font-bold tracking-tight">
            Attack Surface
            <br />
            <span className="brand-gradient bg-clip-text text-transparent">Intelligence</span>
          </p>
          <p className="mt-3 max-w-md text-muted">Narzędzie do cyklicznego skanowania rozległych sieci (powyżej 10 000 adresów IP).</p>
          <ul className="mt-6 space-y-2.5">
            {FEATURES.map((f) => (
              <li key={f.text} className="flex items-center gap-3 text-muted">
                <span className="grid size-7 place-items-center rounded-lg bg-accent/10 text-accent">{f.icon}</span>
                {f.text}
              </li>
            ))}
          </ul>
        </div>
        <p className="text-xs text-muted">Centrum Bezpieczeństwa Informacji AGH</p>
      </section>

      <div className="grid place-items-center p-4">
        <form className="glass animate-rise flex w-full max-w-sm flex-col gap-2 p-7" onSubmit={handleSubmit} aria-describedby={error ? "login-error" : undefined}>
          <span className="brand-gradient mb-2 grid size-11 place-items-center rounded-xl text-white lg:hidden">
            <IconRadar className="size-6" />
          </span>
          <h1 className="text-2xl font-bold tracking-tight">Zaloguj się</h1>
          <p className="mb-3 text-muted">Attack Surface Intelligence</p>
          <label htmlFor="login-user" className="font-medium">
            Użytkownik
          </label>
          <input
            id="login-user"
            autoComplete="username"
            required
            className="py-2"
            value={username}
            aria-invalid={error ? true : undefined}
            onChange={(e) => setUsername(e.target.value)}
          />
          <label htmlFor="login-password" className="mt-1 font-medium">
            Hasło
          </label>
          <input
            id="login-password"
            type="password"
            autoComplete="current-password"
            required
            className="py-2"
            value={password}
            aria-invalid={error ? true : undefined}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button type="submit" className="mt-3 py-2.5" disabled={busy} aria-busy={busy}>
            {busy ? "Logowanie..." : "Zaloguj"}
          </button>
          <p id="login-error" role="alert" className={error ? "mt-2 rounded-lg border border-red/30 bg-red/10 px-3 py-2 text-red" : undefined}>
            {error}
          </p>
        </form>
      </div>
    </main>
  );
}
