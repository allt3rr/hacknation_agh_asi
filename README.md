# Attack Surface Intelligence (ASI)

Narzędzie do cyklicznego, bezpiecznego **discovery scanu** dużych sieci (powyżej 10 000 adresów IP).
ASI skanuje podane adresy IP, zakresy CIDR i domeny: wykrywa aktywne hosty, otwarte porty i usługi,
rozpoznaje technologie webowe, a na koniec sprawdza znane podatności (CVE) wykrytych usług.
Zmiany między przebiegami są zapisywane, a wyniki trafiają do dashboardu, eksportu JSON/CSV/PDF i do DefectDojo.

![Rust](https://img.shields.io/badge/Rust-stable-000000?logo=rust&logoColor=white)
![Axum](https://img.shields.io/badge/Axum-0.8-6E4A7E)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-6-646CFF?logo=vite&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4-06B6D4?logo=tailwindcss&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![nmap](https://img.shields.io/badge/nmap-scanner-4682B4)
![nuclei](https://img.shields.io/badge/nuclei-v3-orange)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## Spis treści

- [O projekcie](#o-projekcie)
- [Stos technologiczny](#stos-technologiczny)
- [Funkcjonalności](#funkcjonalności)
- [Instalacja](#instalacja)
- [Użycie](#użycie)
- [Konfiguracja](#konfiguracja)
- [Role i uprawnienia](#role-i-uprawnienia)
- [Struktura projektu](#struktura-projektu)
- [Wymagania zadania a implementacja](#wymagania-zadania-a-implementacja)
- [Licencja](#licencja)

## O projekcie

Projekt powstał jako odpowiedź na zadanie konkursowe Centrum Bezpieczeństwa Informacji AGH.
W dużej infrastrukturze część systemów jest widoczna tylko okresowo, a jednorazowy skan nie pokazuje
pełnej powierzchni ataku. ASI rozwiązuje to przez:

- **cykliczne skany** w zdefiniowanych oknach czasowych, z automatycznym wznowieniem w kolejnym oknie,
- **adaptacyjny podział** adresów na podgrupy dobierane do szybkości skanowania,
- **porównywanie przebiegów** i obsługę hostów niestabilnych (`unstable` → `inactive` po N nieudanych próbach),
- **bezpieczny fingerprinting** — tylko żądania GET, bez logowania, bez exploitacji.

## Stos technologiczny

| Warstwa | Technologie |
|---|---|
| Backend | Rust, Axum 0.8, Tokio, sqlx, clap |
| Baza danych | PostgreSQL 16 + szyfrowanie pól AES-256-GCM (Encryption at Rest) |
| Skanowanie | nmap (`-sV`), własny prober HTTP/TLS (reqwest + rustls, x509-parser), nuclei v3 |
| Podatności | NVD API 2.0 (CVE, CVSS), nieinwazyjne szablony CVE nuclei |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS 4, Radix UI, cmdk, sonner |
| Bezpieczeństwo | Argon2id (hasła), sesje w cookie, RBAC, dziennik audytu |
| Integracje | DefectDojo (Generic Findings Import), eksport JSON/CSV/PDF |
| Wdrożenie | Docker, Docker Compose |

## Funkcjonalności

### Discovery i identyfikacja usług
- Wczytywanie celów: adresy IP, zakresy CIDR, domeny — ręcznie lub z pliku **CSV / JSON / TXT**.
- Wielowątkowy skan nmap z globalnym limitem pakietów/s, adaptacyjnymi podgrupami i pomiarem czasu trwania.
- Wykrywanie aktywnych hostów, otwartych portów i wersji usług.
- Kontrola zakresu (`Scope::check`) przed każdym połączeniem — skaner nie wychodzi poza zadane cele i porty.

### Fingerprinting HTTP/HTTPS
- Tytuł strony, kod odpowiedzi, nagłówki, ciasteczka (z flagami), certyfikat TLS, łańcuch przekierowań.
- Wykrywanie CMS-ów, frameworków, serwerów aplikacyjnych, urządzeń IoT, paneli administracyjnych i środowisk staging.
- **Własne sygnatury YAML** (nagłówek, ciasteczko, treść, tytuł, ścieżka, hash favicony, banner, hostname, port).
- Ocena „ciekawości” (priorytet analityczny) i tagi.

### Analiza zmian
- Porównanie kolejnych przebiegów: usługi **nowe, znikające i zmienione**.
- Obsługa hostów niestabilnych — ponowne sprawdzanie brakujących i oznaczanie jako nieaktywne po `inactive_after_misses` przebiegach.
- **Korekty wyników** (produkt, wersja, status, severity, właściciel, notatka) zachowywane przy kolejnych skanach, z historią i autorem.

### Podatności
- Korelacja usług z bazą **NVD** (CPE z nmap, normalizacja dostawców i wersji), severity liczone z CVSS.
- Opcjonalne potwierdzenie szablonami **nuclei** — tylko `cve`, bez `dos`, `fuzz`, `intrusive`, `rce`, `sqli`, `default-login`, OOB.
- Poziomy dowodu:

| Dowód | Znaczenie |
|---|---|
| `confirmed` | trafienie nieinwazyjnego szablonu nuclei |
| `version_match` | dokładna wersja mieści się w zakresie podatnych wersji NVD |
| `version_backport` | wersja pakietu dystrybucji — poprawka mogła zostać przeniesiona wstecz |
| `version_conditional` | CVE dotyczy produktu tylko w połączeniu z innym komponentem |

### Harmonogram, raporty i integracje
- Harmonogram cyklicznych skanów złożony z **pozycji** — każda ma własną nazwę, cele, częstotliwość (1–720 h),
  okna czasowe z dniami tygodnia i tryb sprawdzania podatności (`ask` / `auto` / `off`). Ustawiany w interfejsie.
- W danej chwili trwa najwyżej jeden skan — należne pozycje czekają, aż bieżący przebieg się skończy.
- Dashboard z licznikami, technologiami, ciekawymi znaleziskami i ostatnimi zmianami.
- Eksport JSON/CSV (profil `safe` lub `raw`), raport PDF przebiegu, import wyników JSON/CSV.
- **DefectDojo**: automatyczna wysyłka findingów (engagement `ASI <ip>` per host) oraz ręczna ponowna wysyłka.

### Bezpieczeństwo danych
- RBAC z czterema rolami, egzekwowany w każdym handlerze API.
- Szyfrowanie wrażliwych pól AES-256-GCM z AAD per rekord; klucz przechowywany poza wolumenem bazy.
- Redakcja sekretów (np. `authorization`, `cookie`, tokeny) w odpowiedziach API; pełne wartości tylko dla administratora, z wpisem w audycie.
- Limit 5 nieudanych logowań na 15 minut.

## Instalacja

### Wymagania wstępne

- **Docker** 24+ z **Docker Compose** (Docker Desktop na Windows/macOS lub Docker Engine na Linuksie).
- Wolny port `8080` na `127.0.0.1` (można go zmienić zmienną `ASI_PORT`).

### Uruchomienie (Docker)

1. **Utwórz plik `.env`** w katalogu głównym projektu (obok `docker-compose.yml`). Plik jest
   w `.gitignore` — nie trafia do repozytorium.

2. **Wpisz do `.env` sekrety**. Wymagane są dwa:

   | Nazwa | Wymagany | Co wpisać |
   |---|---|---|
   | `ASI_ADMIN_PASSWORD` | tak | hasło konta `admin`, minimum 10 znaków |
   | `ASI_DB_PASSWORD` | tak | hasło bazy PostgreSQL — długi losowy ciąg, np. z `openssl rand -hex 32` |
   | `ASI_DD_URL` | nie | adres DefectDojo, np. `http://host.docker.internal:8081` |
   | `ASI_DD_TOKEN` | nie | token API DefectDojo |
   | `ASI_DD_PRODUCT` | nie | id produktu w DefectDojo |
   | `ASI_NVD_API_KEY` | nie | klucz NVD API (wyższy limit zapytań przy sprawdzaniu CVE) |

   Minimalny plik `.env`:

   ```dotenv
   ASI_ADMIN_PASSWORD=TwojeMocneHaslo123
   ASI_DB_PASSWORD=wstaw-losowy-ciag
   ```

   Integracja z DefectDojo działa tylko wtedy, gdy ustawione są wszystkie trzy zmienne `ASI_DD_*`.
   Klucz szyfrowania danych **nie jest** sekretem do wpisania — generuje go automatycznie usługa `keygen`.

3. **Zbuduj i uruchom kontenery**:

   ```bash
   docker compose up -d --build
   ```

   Pierwsze budowanie trwa kilka minut. Stan usług sprawdzisz poleceniem `docker compose ps`,
   a logi — `docker compose logs -f asi`.

4. **Otwórz aplikację**: **http://127.0.0.1:8080**

Compose uruchamia trzy usługi:
- `db` — PostgreSQL 16,
- `keygen` — jednorazowo generuje klucz szyfrowania w osobnym wolumenie `asi-keys`,
- `asi` — backend z nmap, nuclei i zbudowanym interfejsem.

Zatrzymanie: `docker compose down` (dane zostają w wolumenach). Pełne usunięcie razem z danymi: `docker compose down -v`.

### Logowanie

| Pole | Wartość |
|---|---|
| Login | `admin` |
| Hasło | wartość `ASI_ADMIN_PASSWORD` z pliku `.env` |

Hasło sprawdzisz w pliku `.env` w katalogu głównym projektu:

```bash
grep ASI_ADMIN_PASSWORD .env
```

W PowerShell: `Select-String ASI_ADMIN_PASSWORD .env`.

> Konto `admin` tworzone jest **tylko przy pierwszym starcie, na pustej bazie**. Późniejsza zmiana
> `ASI_ADMIN_PASSWORD` w `.env` nie zmienia hasła — zmienisz je w zakładce **Konfiguracja → Użytkownicy**.
> Jeśli nie pamiętasz hasła, a dane nie są potrzebne, usuń wolumeny (`docker compose down -v`),
> ustaw nowe hasło w `.env` i uruchom kontenery ponownie.

Gdy `ASI_ADMIN_PASSWORD` jest puste lub krótsze niż 10 znaków, kontener `asi` nie wystartuje
(w logach: `Pierwszy start wymaga ASI_ADMIN_PASSWORD`).

## Użycie

### Przez interfejs

1. **Konfiguracja → Cele** — dodaj adresy IP, zakresy CIDR lub domeny ręcznie albo zaimportuj plik CSV/JSON.
2. **Skany → Harmonogram** — dodaj pozycje harmonogramu (cele, częstotliwość, okna czasowe, tryb podatności) albo uruchom skan ręcznie.
3. **Skany → Przebiegi** — śledź postęp, czas trwania i pokrycie; po zakończeniu potwierdź sprawdzenie podatności (**Sprawdzić podatności?**).
4. **Przegląd** — dashboard z najważniejszymi znaleziskami i zmianami względem poprzedniego przebiegu.
5. **Konfiguracja → Sygnatury** — dodawaj własne reguły detekcji.
6. Eksportuj wyniki do JSON/CSV/PDF lub wyślij je do DefectDojo (**CVE → DefectDojo**).

### Import celów z CSV

Obsługiwane są dwa formaty z nagłówkiem:

```csv
target,tags,note
10.0.0.0/24,prod;dmz,Sieć produkcyjna
example.com,web,
```

Format organizatora — kolumna `ip_address` jest celem, a `subnet_cidr`, `network_zone` i `hostname`
stają się tagami `subnet:…`, `zone:…`, `host:…`. Ponowny import nie nadpisuje istniejących celów.

### Własna sygnatura

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

Pewność wyniku: `confidence * (0.6 + 0.4 * udział spełnionych reguł)`.

## Konfiguracja

### Zmienne środowiskowe

| Zmienna | Domyślnie | Opis |
|---|---|---|
| `ASI_ADMIN_PASSWORD` | wymagane przy pierwszym starcie | hasło pierwszego administratora |
| `ASI_DB_PASSWORD` | wymagane | hasło bazy (Docker) |
| `ASI_PORT` | `8080` | port na `127.0.0.1` |
| `ASI_SCAN_CONFIG` | `backend/config/scan.toml` | plik konfiguracji skanu |
| `ASI_SESSION_TTL_HOURS` | `12` | czas życia sesji |
| `ASI_COOKIE_SECURE` | `false` | `true` za HTTPS |
| `ASI_DD_URL`, `ASI_DD_TOKEN`, `ASI_DD_PRODUCT` | — | integracja z DefectDojo (wszystkie trzy albo żadna) |
| `ASI_NVD_API_KEY` | — | klucz NVD API (wyższy limit zapytań) |

### Plik skanu (`backend/config/scan.toml`)

```toml
ports = "21,22,80,443,8000-8100,8443"  # lista dozwolonych portów (domyślnie top_ports = 100)
global_max_rate = 500                  # łączny limit pakietów/s
concurrency = 4                        # równoległe procesy nmap
chunk_size = 64                        # startowy rozmiar podgrupy (adaptacyjny 8–512)
target_chunk_secs = 300                # docelowy czas jednej podgrupy
inactive_after_misses = 3              # po ilu przebiegach host jest nieaktywny

[vuln]
mode = "ask"     # ask | auto | off
verify = false   # potwierdzanie szablonami nuclei
```

> Sekcja `[schedule]` w `scan.toml` jest ignorowana (zostaje dla zgodności) — harmonogram ustawia się w interfejsie lub przez `/api/v1/schedules`.

## Role i uprawnienia

| Uprawnienie | admin | editor | analyst | viewer |
|---|:-:|:-:|:-:|:-:|
| Odczyt i eksport | ✅ | ✅ | ✅ | ✅ |
| Korekty wyników, uruchamianie skanów, DefectDojo | ✅ | ✅ | ❌ | ❌ |
| Edycja istniejących celów i sygnatur | ✅ | ✅ | ✅ | ❌ |
| Dodawanie, import i usuwanie celów i sygnatur | ✅ | ✅ | ❌ | ❌ |
| Użytkownicy, audyt, odsłonięcie wartości ciasteczek | ✅ | ❌ | ❌ | ❌ |

Role odpowiadają wymaganiom zadania: **Administracja**, **Dodawanie/usuwanie/modyfikacja**, **Modyfikacja i odczyt**, **Odczyt**.

## Struktura projektu

```text
.
├── backend/
│   ├── bin/asi/               # punkt wejścia: asi serve | asi migrate
│   ├── crates/
│   │   ├── asi-api/           # REST API (Axum), sesje, RBAC, DefectDojo, raporty
│   │   ├── asi-core/          # model domeny: cele, diff, RBAC, scoring, hasła
│   │   ├── asi-crypto/        # szyfrowanie pól AES-256-GCM
│   │   ├── asi-db/            # PostgreSQL, repozytoria, migracje
│   │   ├── asi-fingerprint/   # silnik sygnatur YAML
│   │   ├── asi-scanner/       # nmap, podgrupy, prober HTTP/TLS, nuclei
│   │   └── asi-vuln/          # klient NVD i korelacja CVE
│   ├── config/scan.toml       # konfiguracja skanu
│   ├── migrations/            # migracje SQL
│   └── signatures/            # wbudowane sygnatury
├── frontend/src/
│   ├── pages/                 # Przegląd (dashboard), Cele, Przebiegi, Harmonogram, Sygnatury, Użytkownicy
│   └── components/            # komponenty UI
├── Dockerfile
└── docker-compose.yml
```

### Testy i kontrola jakości

```bash
# backend/
cargo fmt --check
cargo clippy --all-targets -- -D warnings
DATABASE_URL=postgres://asi:asi@127.0.0.1:5432/asi cargo test

# frontend/
npm run build
npm audit
```

## Wymagania zadania a implementacja

| Wymaganie | Implementacja |
|---|---|
| Wczytanie IP, CIDR, domen (ręcznie, CSV, JSON) | `asi-core/targets.rs`, `/api/v1/targets`, strona Cele |
| Wielowątkowy skan, podgrupy, czas trwania | `asi-scanner` (adaptacyjne podgrupy, workery), `duration_ms` |
| Bezpieczeństwo i tempo | `Scope::check`, limit 256 KiB, `global_max_rate`, tylko GET |
| Okna czasowe, częstotliwość, wznowienie | pozycje harmonogramu `/api/v1/schedules` (tabela `scan_schedules`), `scan_chunks` |
| Aktywne hosty i usługi | `asi-scanner/nmap.rs` |
| HTTP: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | `asi-scanner/http.rs` |
| CMS, framework, serwer, IoT, staging, panele | `backend/signatures/default.yaml`, `asi-fingerprint` |
| Własne sygnatury | `/api/v1/signatures`, strona Sygnatury |
| Porównanie przebiegów, hosty niestabilne | `asi-core/diff.rs`, `asi-db/results.rs` |
| Import/eksport JSON/CSV, DefectDojo | `/results/import`, `/runs/{id}/export`, `/runs/{id}/defectdojo` |
| Edycja niezależna od skanu | `/api/v1/overrides` |
| RBAC, 4 role | `asi-core/rbac.rs` |
| Szyfrowanie danych w spoczynku | `asi-crypto` |
| Dashboard | `/api/v1/dashboard`, strona Dashboard |

## Licencja

Projekt udostępniany na licencji **MIT** — szczegóły w pliku [LICENSE](LICENSE).
Wszystkie zależności mają licencje zgodne z open source (MIT, Apache-2.0, BSD, Zlib i pokrewne).

> ⚠️ Skanuj wyłącznie infrastrukturę, do której masz uprawnienia.
