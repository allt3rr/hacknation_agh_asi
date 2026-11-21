import { useState, type FormEvent } from "react";
import { api } from "../api";
import type { Session } from "../types";
import { errorMessage } from "../utils";

interface LoginPageProps {
  onLogin: (session: Session) => void;
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    try {
      onLogin(await api.login(username, password));
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <form className="mx-auto my-[12vh] flex max-w-[340px] flex-col gap-2 rounded-[10px] border border-line bg-surface p-4" onSubmit={handleSubmit}>
      <h2 className="my-2 text-2xl font-bold">ASI: logowanie</h2>
      <input
        placeholder="Użytkownik"
        autoComplete="username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        placeholder="Hasło"
        type="password"
        autoComplete="current-password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button type="submit">Zaloguj</button>
      {error && <p className="my-3.5 text-red">{error}</p>}
    </form>
  );
}
