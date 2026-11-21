import { useState, type FormEvent } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { useApiData, useNotice } from "../hooks";
import { ROLE_LABELS, ROLES } from "../permissions";
import type { Role, User } from "../types";
import { BTN_SECONDARY, formatDate } from "../utils";

// Musi zgadzać się z MIN_PASSWORD_LENGTH w src/api/users.rs.
const MIN_PASSWORD = 10;

function RoleOptions() {
  return (
    <>
      {ROLES.map((role) => (
        <option key={role} value={role}>
          {ROLE_LABELS[role]}
        </option>
      ))}
    </>
  );
}

export function UsersPage() {
  const { data: users, error, reload } = useApiData(api.users.list);
  const { info, run } = useNotice();

  const changeRole = (user: User, role: Role) =>
    run(async () => {
      await api.users.changeRole(user.id, role);
      info(`Zmieniono rolę użytkownika ${user.username} na: ${ROLE_LABELS[role]}`);
      await reload();
    });

  const remove = (user: User) =>
    run(async () => {
      if (!confirm(`Usunąć użytkownika ${user.username}?`)) return;
      await api.users.remove(user.id);
      await reload();
    });

  return (
    <>
      {error && (
        <p role="alert" className="my-3.5 text-red">
          {error}
        </p>
      )}

      <Card title="Nowy użytkownik">
        <NewUserForm
          onCreate={(username, password, role) =>
            run(async () => {
              await api.users.create(username, password, role);
              info(`Dodano użytkownika ${username}`);
              await reload();
            })
          }
        />
      </Card>

      <Card title="Użytkownicy">
        <DataTable
          rows={users ?? []}
          rowKey={(u) => u.id}
          label="Użytkownicy"
          columns={[
            { header: "Login", render: (u) => u.username },
            {
              header: "Rola",
              render: (u) => (
                <select aria-label={`Rola użytkownika ${u.username}`} value={u.role} onChange={(e) => changeRole(u, e.target.value as Role)}>
                  <RoleOptions />
                </select>
              ),
            },
            { header: "Utworzono", render: (u) => formatDate(u.created_at) },
            {
              header: "",
              render: (u) => (
                <button className={BTN_SECONDARY} aria-label={`Usuń użytkownika ${u.username}`} onClick={() => remove(u)}>
                  Usuń
                </button>
              ),
            },
          ]}
        />
      </Card>
    </>
  );
}

interface NewUserFormProps {
  onCreate: (username: string, password: string, role: Role) => Promise<void>;
}

function NewUserForm({ onCreate }: NewUserFormProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    await onCreate(username, password, role);
    setUsername("");
    setPassword("");
  }

  return (
    <form className="my-2 flex flex-wrap items-center gap-2" onSubmit={handleSubmit}>
      <label htmlFor="new-user-login">Login</label>
      <input id="new-user-login" autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
      <label htmlFor="new-user-password">Hasło</label>
      <input
        id="new-user-password"
        type="password"
        autoComplete="new-password"
        minLength={MIN_PASSWORD}
        aria-describedby="new-user-password-hint"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <span id="new-user-password-hint" className="text-muted">
        min. {MIN_PASSWORD} znaków
      </span>
      <label htmlFor="new-user-role">Rola</label>
      <select id="new-user-role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
        <RoleOptions />
      </select>
      <button type="submit" disabled={!username.trim() || password.length < MIN_PASSWORD}>
        Dodaj
      </button>
    </form>
  );
}
