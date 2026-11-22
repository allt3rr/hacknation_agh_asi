import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { api, setUnauthorizedHandler } from "./api";
import logo from "./assets/logo.png";
import { CookieNotice } from "./components/CookieNotice";
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";
import { RunsPage } from "./pages/RunsPage";
import { SchedulePage } from "./pages/SchedulePage";
import { SignaturesPage } from "./pages/SignaturesPage";
import { TargetsPage } from "./pages/TargetsPage";
import { UsersPage } from "./pages/UsersPage";
import { can, ROLE_LABELS, type Permission } from "./permissions";
import type { Session } from "./types";
import { BTN_SECONDARY, errorMessage } from "./utils";

type TabId = "overview" | "runs" | "schedule" | "targets" | "signatures" | "users";

interface Tab {
  id: TabId;
  label: string;
  requires?: Permission;
}

interface Section {
  id: "overview" | "scans" | "config";
  label: string;
  tabs: Tab[];
}

const SECTIONS: Section[] = [
  { id: "overview", label: "Przegląd", tabs: [{ id: "overview", label: "Przegląd" }] },
  {
    id: "scans",
    label: "Skany",
    tabs: [
      { id: "runs", label: "Przebiegi" },
      { id: "schedule", label: "Harmonogram" },
    ],
  },
  {
    id: "config",
    label: "Konfiguracja",
    tabs: [
      { id: "targets", label: "Cele" },
      { id: "signatures", label: "Sygnatury" },
      { id: "users", label: "Użytkownicy", requires: "admin.users" },
    ],
  },
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
  const [tab, setTab] = useState<TabId>("overview");
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  const visible = SECTIONS.map((s) => ({ ...s, tabs: s.tabs.filter((t) => !t.requires || (session && can(session, t.requires))) }));
  const section = visible.find((s) => s.tabs.some((t) => t.id === tab)) ?? visible[0];
  const tabLabel = section.tabs.find((t) => t.id === tab)?.label ?? "";

  useEffect(() => {
    document.title = session ? `${tabLabel} · ASI` : "Logowanie · ASI";
  }, [tabLabel, session]);

  // Po zmianie sekcji (i po zalogowaniu) fokus trafia na jej nagłówek, żeby czytnik ekranu ogłosił nowy widok.
  useEffect(() => {
    headingRef.current?.focus();
  }, [section.id, session]);

  useEffect(() => {
    api.me().then(setSession, () => setSession(null));
  }, []);

  const startSession = (newSession: Session) => {
    setSession(newSession);
    setLogoutError(null);
    setTab("overview");
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

  const roles = session.roles.map((r) => ROLE_LABELS[r] ?? r).join(", ");

  return (
    <>
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-surface focus:p-2">
        Przejdź do treści
      </a>
      <header className="sticky top-0 z-40 border-b border-line bg-surface">
        <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-x-4 gap-y-1 px-3 py-1.5 lg:px-6">
          {/* granatowe logo na ciemnym motywie staje się białe, inaczej zlewa się z tłem */}
          <img src={logo} alt="ASI" className="h-7 w-auto shrink-0 dark:brightness-0 dark:invert" />
          <nav aria-label="Główna nawigacja" className="flex min-w-0 gap-0.5 overflow-x-auto">
            {visible.map((s) => {
              const active = s.id === section.id;
              return (
                <button
                  key={s.id}
                  aria-current={active ? "page" : undefined}
                  className={`shrink-0 rounded px-2.5 py-1 shadow-none ${active ? "bg-accent/12 font-semibold text-accent" : "bg-transparent text-muted hover:bg-surface-2 hover:text-fg"}`}
                  onClick={() => setTab(s.tabs[0].id)}
                >
                  {s.label}
                </button>
              );
            })}
          </nav>
          <div className="ml-auto flex min-w-0 items-center gap-2">
            <span className="mono min-w-0 truncate text-xs text-muted" title={`${session.username} (${roles})`}>
              {session.username}@{roles}
            </span>
            <button className={BTN_SECONDARY} onClick={logout}>
              Wyloguj
            </button>
          </div>
        </div>
      </header>

      {logoutError && (
        <div role="alert" className="flex flex-wrap items-center gap-3 border-b border-line bg-surface px-4 py-1.5 text-red">
          {logoutError}
          <button className={BTN_SECONDARY} onClick={logout}>
            Ponów
          </button>
        </div>
      )}

      <main id="main" className="mx-auto max-w-[1400px] px-3 py-3 pb-24 lg:px-6">
        <h1 ref={headingRef} tabIndex={-1} className="sr-only">
          {section.label}
        </h1>
        {section.tabs.length > 1 && <Tabs tabs={section.tabs} current={tab} onSelect={setTab} />}
        <div role={section.tabs.length > 1 ? "tabpanel" : undefined} id={`panel-${tab}`} aria-labelledby={section.tabs.length > 1 ? `tab-${tab}` : undefined}>
          <CurrentTab tab={tab} session={session} />
        </div>
      </main>
    </>
  );
}

function Tabs({ tabs, current, onSelect }: { tabs: Tab[]; current: TabId; onSelect: (id: TabId) => void }) {
  const refs = useRef<Partial<Record<TabId, HTMLButtonElement | null>>>({});
  // Strzałki przełączają zakładki (wzorzec ARIA tabs z automatyczną aktywacją).
  const onKeyDown = (e: KeyboardEvent) => {
    const step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const index = tabs.findIndex((t) => t.id === current);
    const next = tabs[(index + step + tabs.length) % tabs.length];
    onSelect(next.id);
    refs.current[next.id]?.focus();
  };
  return (
    <div role="tablist" className="mb-3 flex gap-0.5 overflow-x-auto border-b border-line" onKeyDown={onKeyDown}>
      {tabs.map((t) => {
        const active = t.id === current;
        return (
          <button
            key={t.id}
            ref={(el) => {
              refs.current[t.id] = el;
            }}
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={active}
            aria-controls={`panel-${t.id}`}
            tabIndex={active ? 0 : -1}
            className={`-mb-px shrink-0 rounded-none border-b-2 bg-transparent px-3 py-1.5 shadow-none ${active ? "border-accent font-semibold text-fg" : "border-transparent text-muted hover:text-fg"}`}
            onClick={() => onSelect(t.id)}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

function CurrentTab({ tab, session }: { tab: TabId; session: Session }) {
  switch (tab) {
    case "overview":
      return <DashboardPage session={session} />;
    case "targets":
      return <TargetsPage session={session} />;
    case "runs":
      return <RunsPage session={session} />;
    case "schedule":
      return <SchedulePage session={session} />;
    case "signatures":
      return <SignaturesPage session={session} />;
    case "users":
      return <UsersPage />;
  }
}
