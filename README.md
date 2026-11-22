# ASI: Attack Surface Intelligence

Narzędzie do cyklicznego, bezpiecznego discovery scanu dużych sieci (powyżej 10 000 adresów IP).
Wykrywa aktywne hosty, usługi, technologie webowe, CMS-y, panele, nagłówki i ciasteczka, zapisuje
zmiany między przebiegami, pozwala trwale korygować wyniki, eksportuje JSON/CSV i do DefectDojo.
Po skanie sprawdza znane podatności usług (CVE z NVD, ocena CVSS, opcjonalne potwierdzenie
nieinwazyjnymi szablonami nuclei).
Ma cztery role, szyfrowanie wrażliwych pól i dziennik audytu.

Backend: Rust ([`backend/`](backend/README.md) — Axum, sqlx, PostgreSQL 16). Frontend: React + TypeScript
(Vite, `frontend/`). Skanowanie: nmap + własny prober HTTP/TLS.

## Szybki start (Docker)

```bash
# W pliku .env ustaw ASI_ADMIN_PASSWORD (minimum 10 znaków)
# oraz ASI_DB_PASSWORD (np. osobne losowe hasło z openssl rand -hex 32).
docker compose up -d --build            # http://127.0.0.1:8080
```

Compose uruchamia: `db` (PostgreSQL 16), `keygen` (jednorazowo tworzy klucz szyfrowania w osobnym
wolumenie `asi-keys`, nie w wolumenie bazy) i `asi` (backend ze skanerem nmap i interfejsem pod tym
samym adresem). Konto `admin` powstaje z hasłem startowym wyłącznie na pustej bazie.
W istniejącym wdrożeniu ustaw ASI_DB_PASSWORD zgodnie z aktualnym hasłem roli PostgreSQL.
Rotację hasła bazy skoordynuj ze zmianą hasła tej roli. Hasło konta aplikacji zmienisz w zakładce Użytkownicy.

| Zmienna | Domyślnie | Opis |
|---|---|---|
| `ASI_ADMIN_PASSWORD` | wymagane przy pierwszym starcie | hasło pierwszego administratora |
| `ASI_PORT` | `8080` | port na `127.0.0.1` |
| `ASI_PROJECT` | `asi` | nazwa projektu compose (np. drugi egzemplarz obok) |
| `ASI_DB_PASSWORD` | wymagane | hasło bazy |
| `ASI_SCAN_CONFIG` | `backend/config/scan.toml` | plik konfiguracji skanu (porty, limity, okna czasowe) |
| `ASI_SESSION_TTL_HOURS`, `ASI_COOKIE_SECURE` | `12`, `false` | sesja; `true` za HTTPS |
| `ASI_DD_URL`, `ASI_DD_TOKEN`, `ASI_DD_PRODUCT` | — | DefectDojo (id produktu w `ASI_DD_PRODUCT`): wyniki są wysyłane automatycznie po decyzji o CVE: po zatwierdzonym sprawdzaniu info z opisem CVE (po jego zakończeniu), po odrzuceniu lub w trybie `off` samo info; błąd tylko w logu. Po sprawdzeniu CVE przycisk **CVE → DefectDojo** w tabeli Przebiegi wysyła je ponownie (`POST /api/v1/runs/{id}/defectdojo`). Każdy IP ma własny engagement `ASI <ip>` w statusie „In Progress”: istniejący jest używany ponownie, brakujący tworzony. DefectDojo na hoście: `http://host.docker.internal:8081`. `ASI_DD_ENGAGEMENT` nie jest już używane |
| `ASI_NVD_API_KEY` | — | opcjonalny klucz NVD API (wyższy limit zapytań przy sprawdzaniu podatności) |

## Sprawdzanie podatności

Po zakończonym skanie (tryb „zapytaj”) pojawia się pytanie **Sprawdzić podatności?**. Po akceptacji ASI ustala
produkt i wersję usług (nmap `-sV`, technologie), pobiera CVE z NVD i liczy severity z CVSS; przy `verify = true`
potwierdza je nieinwazyjnymi szablonami nuclei. Wynik: przycisk **CVE** w tabeli Przebiegi. Do DefectDojo
(engagement per IP) wyniki trafiają automatycznie po tej decyzji: z opisem CVE po zakończonym sprawdzaniu albo
same wyniki skanu po **Pomiń** (CVE można sprawdzić później i wysłać przyciskiem **CVE → DefectDojo**).


Sekcja `[vuln]` w pliku konfiguracji skanu: `mode = "ask" | "auto" | "off"` (domyślnie `ask`, nadpisywane przy
starcie skanu), `verify` (nuclei), `nvd_url`, `cache_hours`, `verify_rate`.

Każda podatność ma poziom dowodu (lista sortowana od najpewniejszych):

| Dowód | Kiedy | DefectDojo |
|---|---|---|
| `confirmed` | trafienie nieinwazyjnego szablonu CVE nuclei; CVE spoza wyniku NVD też trafia na listę (ocena z szablonu) | `verified=true` |
| `version_match` | dokładna wersja upstream mieści się w podatnych wersjach NVD | `verified=false` |
| `version_backport` | wersja pakietu dystrybucji (Ubuntu, Debian, RHEL…): poprawka mogła zostać przeniesiona wstecz | `verified=false` |
| `version_conditional` | CVE w NVD dotyczy produktu tylko razem z innym komponentem (konfiguracja AND, np. „na Windows”) — wymagany komponent jest w opisie | `verified=false` |

Identyfikacja usług pod NVD: CPE z nmap (z wersją usługi, gdy CPE jej nie ma), poprawiony dostawca dla nazw
zastąpionych w NVD (`igor_sysoev:nginx` → `f5:nginx`, `mysql:mysql` → `oracle:mysql`), wersje OpenSSH w formacie
słownika NVD (`8.9p1` → wersja `8.9`, update `p1`), CVE wycofane (`Rejected`) są pomijane. Brak odpowiedzi NVD
dla części usług nie przerywa sprawdzania (uwaga w wyniku); bez żadnej odpowiedzi sprawdzanie kończy się błędem.

Nuclei uruchamiane jest tylko z szablonami `cve`, bez tagów `dos`, `fuzz`, `intrusive`, `bruteforce`, `oast`,
`rce`, `sqli`, `file-upload`, `default-login` (nic, co wykonuje kod, modyfikuje dane albo próbuje logowania),
bez OOB (`-ni`), z limitem `verify_rate` i tylko na usługach przebiegu w aktualnym zakresie celów i portów.
Respektuje okno czasowe harmonogramu: poza oknem weryfikacja jest pomijana, a na końcu okna przerywana
(trafienia sprzed przerwania zostają). Usługi oznaczone jako `false_positive` nie mają podatności na liście
ani w DefectDojo.

## Praca lokalna bez Dockera

Wymagania: Rust (stable), Node.js 24, PostgreSQL 16, nmap w `PATH` — szczegóły w [`backend/README.md`](backend/README.md).

```bash
cd frontend && npm ci && npm run build && cd ..
read -rs -p "Hasło pierwszego administratora: " ASI_ADMIN_PASSWORD
export ASI_ADMIN_PASSWORD
export DATABASE_URL=postgres://asi:asi@127.0.0.1:5432/asi ASI_DEMO_KEY=1 ASI_STATIC_DIR=../frontend/dist
(cd backend && cargo run -p asi -- serve)                    # http://127.0.0.1:8080
cd frontend && ASI_API=http://127.0.0.1:8080 npm run dev     # tryb deweloperski na :5173
```

Kontrole: w `backend/` — `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`DATABASE_URL=… cargo test`; w `frontend/` — `npm run build`, `npm audit`.

## Wymagania zadania a implementacja

| Wymaganie | Gdzie |
|---|---|
| Wczytanie IP, CIDR, domen (ręcznie, CSV, JSON; plik organizatora z `ip_address`) | `asi-core/targets.rs`, `/api/v1/targets`, strona Cele |
| Wielowątkowy skan nmap, podgrupy, czas trwania | `asi-scanner` (adaptacyjne podgrupy, workery), `scan_runs.coverage`, `duration_ms` |
| Bezpieczeństwo i tempo | `Scope::check` przed każdym połączeniem, limit 256 KiB, `global_max_rate`, tylko GET |
| Okna czasowe, częstotliwość, wznowienie | `asi-scanner/config.rs`, harmonogram w `asi-api/scans.rs`, `scan_chunks`; ustawianie z interfejsu: zakładka Harmonogram (`GET/PUT /api/v1/schedule`, tabela `scan_schedule`) |
| Aktywne hosty i usługi | `asi-scanner/nmap.rs` (argumenty jako lista, `-iL -`) |
| HTTP: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | `asi-scanner/http.rs` |
| CMS, framework, serwer, IoT, staging, panele | `backend/signatures/default.yaml`, `asi-fingerprint` |
| Własne sygnatury | `/api/v1/signatures`, strona Sygnatury |
| Porównanie przebiegów, hosty niestabilne | `asi-core/diff.rs`, `asi-db/results.rs` (`unstable` → `inactive`) |
| Import i eksport JSON/CSV, DefectDojo (engagement per IP) | `/api/v1/results/import`, `/runs/{id}/export`, `/runs/{id}/defectdojo` |
| Podatności usług: CVE, CVSS, severity | `asi-core/vuln.rs`, `asi-vuln` (NVD), `asi-scanner/nuclei.rs`, `/runs/{id}/vuln-check`, `/runs/{id}/vuln-check/skip`, `/runs/{id}/vulnerabilities` |
| Edycja niezależna od skanu | korekty `/api/v1/overrides` nakładane na widok i eksport |
| RBAC, 4 role | `asi-core/rbac.rs` (macierz §14.1), kontrola w każdym handlerze |
| Szyfrowanie pól | `asi-crypto` (AES-256-GCM, AAD per rekord), redakcja sekretów w API |
| Dashboard | `/api/v1/dashboard` (liczniki w SQL), strona Dashboard |

## Role

| Uprawnienie | admin | editor | analyst | viewer |
|---|---|---|---|---|
| Odczyt i eksport | tak | tak | tak | tak |
| Korekty wyników, konfiguracja i uruchamianie skanów, DefectDojo | tak | tak | tak | nie |
| Dodawanie, import i usuwanie celów, tworzenie i usuwanie sygnatur | tak | tak | nie | nie |
| Edycja istniejących celów i sygnatur | tak | tak | tak | nie |
| Użytkownicy, audyt, odsłonięcie wartości ciasteczek | tak | nie | nie | nie |

Frontend ukrywa niedostępne przyciski na podstawie uprawnień z `/api/v1/me`; dostęp egzekwuje backend.

## Sygnatury

Pliki `backend/signatures/*.yaml` lub strona Sygnatury. Typy reguł: `header`, `cookie`, `body`, `title`,
`path` (GET bez logowania, tylko ścieżka w obrębie usługi, np. `/admin`), `favicon_sha256`, `service`
(banner z nmap), `hostname`, `port`. Pewność = `confidence * (0.6 + 0.4 * udział spełnionych reguł)`.

```yaml
- id: grafana
  name: Grafana
  category: application   # cms, framework, server, application, iot, admin_panel, staging, interesting
  confidence: 85
  match: any              # any albo all
  rules:
    - type: title
      regex: '^Grafana'
```

## Struktura repozytorium

- [backend/](backend/README.md) zawiera aplikację PostgreSQL, migracje, konfigurację i wbudowane sygnatury.
- [frontend/](frontend/) zawiera interfejs React, klienta API i zasoby interfejsu.
