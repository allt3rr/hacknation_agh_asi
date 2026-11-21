import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { api, setUnauthorizedHandler } from "./api";
import { CookieNotice } from "./components/CookieNotice";
import { IconCalendar, IconDashboard, IconLogout, IconRadar, IconShield, IconTarget, IconUsers } from "./components/icons";
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

type PageId = "dashboard" | "targets" | "runs" | "schedule" | "signatures" | "users";

interface PageDefinition {
  id: PageId;
  label: string;
  /** Jedno zdanie pod nagłówkiem strony: co tu jest i po co. */
  description: string;
  icon: ReactNode;
  requires?: Permission;
}

const PAGES: PageDefinition[] = [
  { id: "dashboard", label: "Dashboard", description: "Najważniejsze znaleziska i zmiany z ostatniego skanu.", icon: <IconDashboard /> },
  { id: "targets", label: "Cele", description: "Lista adresów IP, zakresów CIDR i domen do skanowania: wprowadzanie ręczne lub z pliku CSV/JSON.", icon: <IconTarget /> },
  { id: "runs", label: "Skany", description: "Przebiegi skanu, wykryte usługi, porównanie wyników między przebiegami, import i eksport (JSON, CSV).", icon: <IconRadar /> },
  { id: "schedule", label: "Harmonogram", description: "Przedziały czasowe uruchomienia i częstotliwość automatycznych skanów.", icon: <IconCalendar /> },
  { id: "signatures", label: "Sygnatury", description: "Własne sygnatury detekcyjne: nagłówki, ciasteczka, fragmenty HTML, ścieżki bez prób logowania.", icon: <IconShield /> },
  { id: "users", label: "Użytkownicy", description: "Konta użytkowników i role (RBAC).", icon: <IconUsers />, requires: "admin.users" },
];

/** Znak marki: radar w gradiencie. */
function BrandMark({ className = "size-8" }: { className?: string }) {
  return (
    <span className={`brand-gradient grid shrink-0 place-items-center rounded-xl text-white shadow-[0_8px_24px_-8px_var(--glow)] ${className}`}>
      <IconRadar className="size-[60%]" />
    </span>
  );
}

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
  const headingRef = useRef<HTMLHeadingElement>(null);
  const current = PAGES.find((p) => p.id === page);
  const label = current?.label ?? "";

  useEffect(() => {
    document.title = session ? `${label} · ASI` : "Logowanie · ASI";
  }, [label, session]);

  // Po zmianie strony (i po zalogowaniu) fokus trafia na jej nagłówek, żeby czytnik ekranu ogłosił nowy widok.
  useEffect(() => {
    headingRef.current?.focus();
  }, [page, session]);

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
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-surface focus:p-2">
        Przejdź do treści
      </a>
      <div className="lg:grid lg:grid-cols-[15.5rem_1fr]">
        <aside className="sticky top-0 z-40 border-b border-line bg-surface/80 backdrop-blur-md lg:h-screen lg:border-r lg:border-b-0">
          <div className="flex items-center gap-3 px-4 py-3 lg:px-5 lg:py-5">
            <BrandMark />
            <div className="min-w-0">
              <strong className="block leading-tight">ASI</strong>
              <span className="block truncate text-xs text-muted">Attack Surface Intelligence</span>
            </div>
            <button className={`${BTN_SECONDARY} ml-auto flex items-center gap-1.5 lg:hidden`} onClick={logout}>
              <IconLogout className="size-4" />
              Wyloguj
            </button>
          </div>
          <nav aria-label="Główna nawigacja" className="flex gap-1 overflow-x-auto px-3 pb-3 lg:flex-col lg:px-3 lg:pb-0">
            {visiblePages.map((p) => {
              const active = p.id === page;
              return (
                <button
                  key={p.id}
                  aria-current={active ? "page" : undefined}
                  className={`flex shrink-0 items-center gap-3 rounded-lg px-3 py-2 text-left shadow-none hover:translate-y-0 hover:shadow-none ${
                    active ? "bg-accent/12 font-semibold text-accent ring-1 ring-accent/30" : "bg-transparent text-muted hover:bg-surface-2 hover:text-fg"
                  }`}
                  onClick={() => setPage(p.id)}
                >
                  {p.icon}
                  {p.label}
                </button>
              );
            })}
          </nav>
          <div className="mt-auto hidden border-t border-line p-4 lg:absolute lg:inset-x-0 lg:bottom-0 lg:block">
            <div className="mb-3 flex items-center gap-3">
              <span aria-hidden="true" className="grid size-9 place-items-center rounded-full bg-surface-2 font-semibold uppercase">
                {session.username.slice(0, 1)}
              </span>
              <div className="min-w-0">
                <div className="truncate font-medium">{session.username}</div>
                <div className="truncate text-xs text-muted">{session.roles.map((r) => ROLE_LABELS[r] ?? r).join(", ")}</div>
              </div>
            </div>
            <button className={`${BTN_SECONDARY} flex w-full items-center justify-center gap-2`} onClick={logout}>
              <IconLogout className="size-4" />
              Wyloguj
            </button>
          </div>
        </aside>

        <div className="min-w-0">
          {logoutError && (
            <div role="alert" className="flex flex-wrap items-center gap-3 border-b border-line bg-surface px-4 py-2 text-red">
              {logoutError}
              <button className={BTN_SECONDARY} onClick={logout}>
                Ponów
              </button>
            </div>
          )}
          <main id="main" className="mx-auto max-w-[1300px] px-4 py-6 pb-28 lg:px-8">
            <header className="animate-rise mb-6">
              <h1 ref={headingRef} tabIndex={-1} className="text-3xl font-bold tracking-tight outline-none">
                {label}
              </h1>
              <p className="mt-1 text-muted">{current?.description}</p>
              <p className="mt-1 text-xs text-muted lg:hidden">
                Zalogowano: {session.username} ({session.roles.map((r) => ROLE_LABELS[r] ?? r).join(", ")})
              </p>
            </header>
            <CurrentPage page={page} session={session} />
          </main>
        </div>
      </div>
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
    case "schedule":
      return <SchedulePage session={session} />;
    case "signatures":
      return <SignaturesPage session={session} />;
    case "users":
      return <UsersPage />;
  }
}
