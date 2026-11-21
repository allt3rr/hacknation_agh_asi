import { useState, type FormEvent } from "react";
import { api, ApiError } from "../api";
import type { Session } from "../types";
import { errorMessage } from "../utils";

interface LoginPageProps {
  onLogin: (session: Session) => void;
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
    <main>
      <form
        className="mx-auto my-[12vh] flex max-w-[340px] flex-col gap-2 rounded-[10px] border border-line bg-surface p-4"
        onSubmit={handleSubmit}
        aria-describedby={error ? "login-error" : undefined}
      >
        <h1 className="my-2 text-2xl font-bold">ASI: logowanie</h1>
        <p className="text-muted">Attack Surface Intelligence</p>
        <label htmlFor="login-user">Użytkownik</label>
        <input
          id="login-user"
          autoComplete="username"
          required
          value={username}
          aria-invalid={error ? true : undefined}
          onChange={(e) => setUsername(e.target.value)}
        />
        <label htmlFor="login-password">Hasło</label>
        <input
          id="login-password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          aria-invalid={error ? true : undefined}
          onChange={(e) => setPassword(e.target.value)}
        />
        <button type="submit" className="mt-2" disabled={busy} aria-busy={busy}>
          {busy ? "Logowanie..." : "Zaloguj"}
        </button>
        <p id="login-error" role="alert" className={error ? "my-3.5 text-red" : undefined}>
          {error}
        </p>
      </form>
    </main>
  );
}
