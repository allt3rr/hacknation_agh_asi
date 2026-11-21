# ASI: Attack Surface Intelligence

Prototyp narzędzia do cyklicznego discovery scanu dużych sieci (powyżej 10 000 adresów IP).
Wykrywa aktywne hosty, usługi, technologie webowe, CMS-y, nagłówki i ciasteczka oraz zapisuje
zmiany między kolejnymi skanami. Ma integrację z DefectDojo, role użytkowników i szyfrowanie
danych w bazie.

Backend: Rust (axum, sqlx, SQLite). Frontend: React + TypeScript (Vite). Skanowanie: nmap.

## Struktura projektu

```
src/
  main.rs            komendy CLI (serve, scan, import-targets, gen-key)
  config.rs          konfiguracja z config/asi.toml
  state.rs           stan aplikacji współdzielony przez API i harmonogram
  input.rs           parsowanie celów: IP, CIDR, domeny (tekst, CSV, JSON)
  scanner/
    mod.rs           kolejka podgrup, równoległe procesy nmap, przerwanie po końcu okna
    nmap.rs          uruchomienie nmap i parsowanie XML
    http.rs          tytuł, kod, nagłówki, ciasteczka, certyfikat TLS, przekierowania
  fingerprint.rs     silnik sygnatur YAML
  diff.rs            porównanie skanów: nowe, znikające, zmienione usługi
  pipeline.rs        pełny przebieg skanu i import wyników
  scheduler.rs       okna czasowe i częstotliwość skanów
  auth.rs            role, uprawnienia, hasła, sesje
  defectdojo.rs      eksport findingów do DefectDojo
  export.rs          eksport i import JSON/CSV
  api/               endpointy REST, jeden plik na obszar (targets, runs, users, ...)
  db/                zapytania SQL, jeden plik na tabelę; crypto.rs szyfruje pola
frontend/src/
  App.tsx            nawigacja i sesja
  api.ts             klient REST
  types.ts           typy odpowiedzi API
  pages/             widoki: Dashboard, Cele, Skany, Sygnatury, Użytkownicy
  components/        wspólne komponenty (tabela, karta, komunikaty)
signatures/          wbudowane sygnatury
migrations/          schemat bazy
docker/              entrypoint kontenera
```

## Uruchomienie lokalne

Wymagania: Rust (stable), Node.js 20, nmap w `PATH`.

```bash
cp .env.example .env
cargo run -- gen-key                  # wynik wpisz do ASI_DATA_KEY w .env

cd frontend && npm install && npm run build && cd ..

cargo run -- import-targets examples/targets.csv
cargo run -- serve                    # http://127.0.0.1:8080
```

Przy pierwszym starcie tworzone jest konto `admin`. Hasło jest brane z `ASI_ADMIN_PASSWORD`,
a jeśli jej nie ustawiono, generowane i wypisywane w logu.

Praca nad frontendem z automatycznym przeładowaniem:

```bash
cargo run -- serve                    # backend na :8080
cd frontend && npm run dev            # frontend na :5173, /api przekierowane do backendu
```

Testy backendu: `cargo test`. Sprawdzenie typów frontendu: `npm run typecheck`.

## Docker

```bash
docker compose up -d --build          # skaner i dashboard: http://127.0.0.1:8080
docker compose logs asi               # tu znajdziesz wygenerowane hasło admina
```

Laboratorium do sprawdzenia detekcji (nginx, Apache httpd, Tomcat, WordPress z MariaDB
w wewnętrznej sieci 172.30.0.0/24):

```bash
docker compose --profile lab up -d --build
docker compose run --rm asi import-targets examples/lab-targets.txt
```

Następnie w dashboardzie: Skany, Uruchom skan.

| Plik | Opis |
|---|---|
| `Dockerfile` | trzy etapy: build frontendu (Node), build backendu (Rust), obraz `debian:bookworm-slim` z nmap; aplikacja działa jako użytkownik `asi` |
| `docker/entrypoint.sh` | gdy brak `ASI_DATA_KEY`, generuje klucz w wolumenie danych (tylko do testów) |
| `docker-compose.yml` | usługa `asi` (port tylko na 127.0.0.1, wolumen `asi-data`) i profil `lab` |

Komendy CLI w kontenerze uruchamiaj przez `docker compose run --rm asi <komenda>`, a nie `exec`,
żeby przeszły przez entrypoint i dostały klucz danych.

Bez uprawnień roota nmap używa skanu `connect()`. SYN scan i wykrywanie hostów przez ICMP
wymagają odkomentowania w `docker-compose.yml` opcji `user: root` i `cap_add: [NET_RAW, NET_ADMIN]`.

## Wymagania zadania a implementacja

| Wymaganie | Gdzie |
|---|---|
| Wczytanie IP, CIDR, domen (ręcznie, CSV, JSON) | `input.rs`, `api/targets.rs`, strona Cele |
| Wielowątkowy skan nmap, podział na podgrupy, czas trwania | `scanner/mod.rs`, statystyki `chunks` i `duration_secs` przebiegu |
| Ograniczanie tempa | `global_max_rate` dzielony na procesy (`--max-rate`), `http_concurrency` |
| Okna czasowe, częstotliwość, wznowienie przerwanego skanu | `scheduler.rs`, `scan_runs.pending_json` |
| Aktywne hosty i usługi | `scanner/nmap.rs` |
| Tytuł, kod HTTP, nagłówki, ciasteczka, TLS, przekierowania | `scanner/http.rs` |
| CMS, framework, serwer, IoT, staging, panel administracyjny | `signatures/default.yaml`, `fingerprint.rs` |
| Własne sygnatury | `api/signatures.rs`, strona Sygnatury |
| Porównanie skanów, nowe, znikające i zmienione usługi | `diff.rs`, `GET /api/runs/:id/changes`, `GET /api/diff?from=&to=` |
| Hosty niestabilne | `db/hosts.rs` (active, unstable, inactive), ponowny pomiar w `pipeline.rs` |
| Import wyników JSON/CSV przetwarzany jak skan | `pipeline::import_results` |
| Eksport JSON/CSV | `GET /api/runs/:id/export?format=json` lub `csv` |
| Edycja danych niezależnie od skanu | cele i adnotacje są w osobnych tabelach niż wyniki |
| RBAC i cztery role | `auth.rs` |
| Szyfrowanie danych w spoczynku | `db/crypto.rs` (AES-256-GCM) |
| DefectDojo | `defectdojo.rs`, przycisk na stronie Skany |
| Dashboard | `api/dashboard.rs`, `frontend/src/pages/DashboardPage.tsx` |

## Role

| Uprawnienie | admin | editor | analyst | viewer |
|---|---|---|---|---|
| Odczyt | tak | tak | tak | tak |
| Modyfikacja celów i adnotacji | tak | tak | tak | nie |
| Dodawanie i import | tak | tak | nie | nie |
| Usuwanie | tak | tak | nie | nie |
| Uruchamianie skanów | tak | tak | nie | nie |
| Zarządzanie sygnaturami | tak | tak | nie | nie |
| Zarządzanie użytkownikami | tak | nie | nie | nie |

Frontend ukrywa niedostępne przyciski, ale uprawnienia sprawdza zawsze backend.

## Sygnatury

Pliki `signatures/*.yaml` lub formularz na stronie Sygnatury. Typy reguł: `header`, `cookie`,
`body`, `title`, `path` (żądanie GET bez logowania), `favicon_sha256`, `service` (banner z nmap),
`hostname`, `port`.

```yaml
- id: grafana
  name: Grafana
  category: application   # cms, framework, server, application, iot, admin_panel, staging, interesting
  confidence: 85          # bazowa pewność 0-100
  match: any              # any albo all
  rules:
    - type: title
      regex: '^Grafana'
    - type: body
      regex: 'grafana-app'
```

Pewność detekcji = `confidence * (0.6 + 0.4 * udział spełnionych reguł)`.

## Bezpieczeństwo skanera

- tylko discovery: `nmap -sV --version-light`, bez skryptów NSE typu exploit lub brute force,
- żądania HTTP wyłącznie metodą GET, bez prób logowania i bez przekierowań na inny host,
- globalny limit pakietów na sekundę i limit równoległych połączeń HTTP,
- limit liczby celów (`max_targets`) i rozmiaru zakresu CIDR.

## Do zrobienia

- sondowanie HTTP z nagłówkiem `Host` dla celów będących domenami, odczyt SAN z certyfikatów,
- hash favicony w formacie mmh3 (zgodny z Shodan),
- wykrywanie różnic zależnych od pory dnia,
- ocena priorytetu analitycznego znalezisk,
- `reimport-scan` w DefectDojo i wysyłka surowego XML z nmap,
- limit prób logowania, trwałe sesje, dziennik zmian.
