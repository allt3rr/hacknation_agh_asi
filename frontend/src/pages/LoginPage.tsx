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
    <form className="card login" onSubmit={handleSubmit}>
      <h2>ASI: logowanie</h2>
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
      {error && <p className="notice error">{error}</p>}
    </form>
  );
}
