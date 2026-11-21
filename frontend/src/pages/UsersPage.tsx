import { useState, type FormEvent } from "react";
import { api } from "../api";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { NoticeBar } from "../components/NoticeBar";
import { useApiData, useNotice } from "../hooks";
import { ROLES } from "../permissions";
import type { Role, User } from "../types";
import { BTN_SECONDARY, formatDate } from "../utils";

export function UsersPage() {
  const { data: users, error, reload } = useApiData(api.users.list);
  const { notice, info, run } = useNotice();

  const update = (user: User, patch: { role?: Role; password?: string; disabled?: boolean }, message: string) =>
    run(async () => {
      await api.users.update(user.id, patch);
      info(message);
      await reload();
    });

  const resetPassword = (user: User) => {
    const password = prompt(`Nowe hasło dla ${user.username} (min. 10 znaków). Aktywne sesje zostaną zakończone.`);
    if (password) update(user, { password }, `Zmieniono hasło użytkownika ${user.username}`);
  };

  const remove = (user: User) =>
    run(async () => {
      if (!confirm(`Usunąć użytkownika ${user.username}?`)) return;
      await api.users.remove(user.id);
      await reload();
    });

  return (
    <>
      <NoticeBar notice={notice} />
      {error && <p className="my-3.5 text-red">{error}</p>}

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
          columns={[
            { header: "Login", render: (u) => u.username },
            {
              header: "Rola",
              render: (u) => (
                <select
                  aria-label={`Rola ${u.username}`}
                  value={u.roles[0] ?? "viewer"}
                  onChange={(e) => update(u, { role: e.target.value as Role }, `Zmieniono rolę użytkownika ${u.username}`)}
                >
                  {ROLES.map((role) => (
                    <option key={role}>{role}</option>
                  ))}
                </select>
              ),
            },
            {
              header: "Aktywne",
              render: (u) => (
                <input
                  type="checkbox"
                  aria-label={`Konto ${u.username} aktywne`}
                  checked={!u.disabled}
                  onChange={(e) =>
                    update(u, { disabled: !e.target.checked }, e.target.checked ? `Odblokowano ${u.username}` : `Zablokowano ${u.username}`)
                  }
                />
              ),
            },
            { header: "Utworzono", render: (u) => formatDate(u.created_at) },
            {
              header: "",
              render: (u) => (
                <div className="flex gap-1">
                  <button className={BTN_SECONDARY} onClick={() => resetPassword(u)}>
                    Reset hasła
                  </button>
                  <button className={BTN_SECONDARY} onClick={() => remove(u)}>
                    Usuń
                  </button>
                </div>
              ),
            },
          ]}
        />
      </Card>
    </>
  );
}

function NewUserForm({ onCreate }: { onCreate: (username: string, password: string, role: Role) => Promise<void> }) {
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
      <input aria-label="Login" placeholder="login" value={username} onChange={(e) => setUsername(e.target.value)} />
      <input
        aria-label="Hasło"
        placeholder="hasło (min. 10 znaków)"
        type="password"
        autoComplete="new-password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <select aria-label="Rola" value={role} onChange={(e) => setRole(e.target.value as Role)}>
        {ROLES.map((r) => (
          <option key={r}>{r}</option>
        ))}
      </select>
      <button type="submit" disabled={!username || password.length < 10}>
        Dodaj
      </button>
    </form>
  );
}
