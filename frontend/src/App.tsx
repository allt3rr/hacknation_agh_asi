import { useCallback, useEffect, useState } from "react";
import { api, setAuthToken, setUnauthorizedHandler } from "./api";
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";
import { RunsPage } from "./pages/RunsPage";
import { SignaturesPage } from "./pages/SignaturesPage";
import { TargetsPage } from "./pages/TargetsPage";
import { UsersPage } from "./pages/UsersPage";
import { can, type Permission } from "./permissions";
import { clearSession, loadSession, saveSession } from "./session";
import type { Role, Session } from "./types";
import { BTN_SECONDARY } from "./utils";

type PageId = "dashboard" | "targets" | "runs" | "signatures" | "users";

interface PageDefinition {
  id: PageId;
  label: string;
  requires?: Permission;
}

const PAGES: PageDefinition[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "targets", label: "Cele" },
  { id: "runs", label: "Skany" },
  { id: "signatures", label: "Sygnatury" },
  { id: "users", label: "Użytkownicy", requires: "users" },
];

function restoreSession(): Session | null {
  const session = loadSession();
  // Token ustawiamy od razu, zanim strony zaczną pobierać dane.
  setAuthToken(session?.token ?? null);
  return session;
}

export function App() {
  const [session, setSession] = useState<Session | null>(restoreSession);
  const [page, setPage] = useState<PageId>("dashboard");

  const startSession = (newSession: Session) => {
    setAuthToken(newSession.token);
    saveSession(newSession);
    setSession(newSession);
    setPage("dashboard");
  };

  const endSession = useCallback(() => {
    setAuthToken(null);
    clearSession();
    setSession(null);
  }, []);

  const logout = async () => {
    await api.logout().catch(() => undefined);
    endSession();
  };

  useEffect(() => {
    setUnauthorizedHandler(endSession);
  }, [endSession]);

  if (!session) {
    return <LoginPage onLogin={startSession} />;
  }

  const visiblePages = PAGES.filter((p) => !p.requires || can(session.role, p.requires));

  return (
    <>
      <header className="flex flex-wrap items-center gap-3 border-b border-line bg-surface px-4 py-2.5">
        <strong>ASI</strong>
        <nav>
          {visiblePages.map((p) => (
            <button key={p.id} className={`px-2.5 py-1.5 ${p.id === page ? "bg-bg text-fg" : "bg-transparent text-muted"}`} onClick={() => setPage(p.id)}>
              {p.label}
            </button>
          ))}
        </nav>
        <span className="flex-1" />
        <span className="text-muted">
          {session.username} ({session.role})
        </span>
        <button className={BTN_SECONDARY} onClick={logout}>
          Wyloguj
        </button>
      </header>
      <main className="mx-auto max-w-[1300px] px-4 py-5">
        <CurrentPage page={page} role={session.role} />
      </main>
    </>
  );
}

function CurrentPage({ page, role }: { page: PageId; role: Role }) {
  switch (page) {
    case "dashboard":
      return <DashboardPage />;
    case "targets":
      return <TargetsPage role={role} />;
    case "runs":
      return <RunsPage role={role} />;
    case "signatures":
      return <SignaturesPage role={role} />;
    case "users":
      return <UsersPage />;
  }
}
