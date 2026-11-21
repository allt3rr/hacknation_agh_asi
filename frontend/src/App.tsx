import { useCallback, useEffect, useState } from "react";
import { api, setUnauthorizedHandler } from "./api";
import { CookieNotice } from "./components/CookieNotice";
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";
import { RunsPage } from "./pages/RunsPage";
import { SignaturesPage } from "./pages/SignaturesPage";
import { TargetsPage } from "./pages/TargetsPage";
import { UsersPage } from "./pages/UsersPage";
import { can, type Permission } from "./permissions";
import type { Session } from "./types";
import { BTN_SECONDARY, errorMessage } from "./utils";

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
  { id: "users", label: "Użytkownicy", requires: "admin.users" },
];

export function App() {
  return (
    <>
      <Shell />
      <CookieNotice />
    </>
  );
}

function Shell() {
  // undefined: jeszcze sprawdzamy ciasteczko sesji przez /api/v1/me
  const [session, setSession] = useState<Session | null | undefined>(undefined);
  const [page, setPage] = useState<PageId>("dashboard");
  const [logoutError, setLogoutError] = useState<string | null>(null);

  useEffect(() => {
    api.me().then(setSession, () => setSession(null));
  }, []);

  const startSession = (newSession: Session) => {
    setSession(newSession);
    setLogoutError(null);
    setPage("dashboard");
  };

  const endSession = useCallback(() => setSession(null), []);

  // ekran logowania dopiero po potwierdzeniu przez serwer; przy błędzie można ponowić
  const logout = async () => {
    try {
      await api.logout();
      setLogoutError(null);
      endSession();
    } catch (e) {
      setLogoutError(`Nie udało się wylogować: ${errorMessage(e)}`);
    }
  };

  useEffect(() => {
    setUnauthorizedHandler(endSession);
  }, [endSession]);

  if (session === undefined) {
    return null;
  }
  if (!session) {
    return <LoginPage onLogin={startSession} />;
  }

  const visiblePages = PAGES.filter((p) => !p.requires || can(session, p.requires));

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
          {session.username} ({session.roles.join(", ")})
        </span>
        <button className={BTN_SECONDARY} onClick={logout}>
          Wyloguj
        </button>
      </header>
      {logoutError && (
        <div role="alert" className="flex flex-wrap items-center gap-3 border-b border-line bg-surface px-4 py-2 text-red">
          {logoutError}
          <button className={BTN_SECONDARY} onClick={logout}>
            Ponów
          </button>
        </div>
      )}
      <main className="mx-auto max-w-[1300px] px-4 py-5 pb-24">
        <CurrentPage page={page} session={session} />
      </main>
    </>
  );
}

function CurrentPage({ page, session }: { page: PageId; session: Session }) {
  switch (page) {
    case "dashboard":
      return <DashboardPage />;
    case "targets":
      return <TargetsPage session={session} />;
    case "runs":
      return <RunsPage session={session} />;
    case "signatures":
      return <SignaturesPage session={session} />;
    case "users":
      return <UsersPage />;
  }
}
