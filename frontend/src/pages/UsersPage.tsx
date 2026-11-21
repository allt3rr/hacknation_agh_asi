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

  const changeRole = (user: User, role: Role) =>
    run(async () => {
      await api.users.changeRole(user.id, role);
      info(`Zmieniono rolę użytkownika ${user.username}`);
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
                <select value={u.role} onChange={(e) => changeRole(u, e.target.value as Role)}>
                  {ROLES.map((role) => (
                    <option key={role}>{role}</option>
                  ))}
                </select>
              ),
            },
            { header: "Utworzono", render: (u) => formatDate(u.created_at) },
            {
              header: "",
              render: (u) => (
                <button className={BTN_SECONDARY} onClick={() => remove(u)}>
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
      <input placeholder="login" value={username} onChange={(e) => setUsername(e.target.value)} />
      <input
        placeholder="hasło (min. 10 znaków)"
        type="password"
        autoComplete="new-password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
        {ROLES.map((r) => (
          <option key={r}>{r}</option>
        ))}
      </select>
      <button type="submit" disabled={!username || !password}>
        Dodaj
      </button>
    </form>
  );
}
