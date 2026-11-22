# ASI backend (PostgreSQL)

Backend ASI korzysta z PostgreSQL 16.

| Crate | Zakres |
|---|---|
| `crates/asi-core` | role i uprawnienia (§14.1), Argon2id, tokeny sesji, parser celów; bez I/O |
| `crates/asi-crypto` | AES-256-GCM per pole (AAD `tabela:kolumna:id`), źródło klucza |
| `crates/asi-fingerprint` | sygnatury YAML (pasywna detekcja), ścieżki tylko w obrębie originu |
| `crates/asi-scanner` | nmap (argumenty jako lista), podgrupy, sondy HTTP/TLS z kontrolą zakresu, limitem 256 KiB i wspólnym terminem |
| `crates/asi-db` | pula PostgreSQL, migracje (`migrations/`), seed ról, konto admina, repozytoria |
| `crates/asi-api` | Axum 0.8: logowanie, sesja w cookie, RBAC, healthcheck |
| `bin/asi` | `asi serve` i `asi migrate` |

## Uruchomienie lokalne

```bash
docker run -d --name asi-pg -e POSTGRES_USER=asi -e POSTGRES_PASSWORD=asi -e POSTGRES_DB=asi \
  -p 127.0.0.1:5432:5432 postgres:16-alpine
export DATABASE_URL=postgres://asi:asi@127.0.0.1:5432/asi
export ASI_MASTER_KEY_FILE=$PWD/master.key   # 32 bajty base64, np. openssl rand -base64 32 > master.key
read -rs -p "Hasło administratora: " ASI_ADMIN_PASSWORD
export ASI_ADMIN_PASSWORD
cargo run -p asi -- serve
```

Na pustej bazie ustaw hasło startowe o długości co najmniej 10 znaków.

Testy wymagają działającego PostgreSQL; `#[sqlx::test]` tworzy osobną bazę dla każdego testu:

```bash
DATABASE_URL=postgres://asi:asi@127.0.0.1:5432/asi cargo test
```

## Kontrakt dla frontendu i wdrożenia

| Zmienna | Domyślnie | Opis |
|---|---|---|
| `DATABASE_URL` | — (wymagana) | adres PostgreSQL; bez niej lub przy nieosiągalnej bazie proces kończy się kodem 1 |
| `ASI_MASTER_KEY` / `ASI_MASTER_KEY_FILE` | — (wymagany dla `serve`) | klucz szyfrowania pól (32 bajty base64); nie trzymaj go na wolumenie bazy |
| `ASI_DEMO_KEY` | — | `1` = klucz losowy w pamięci (tylko demo; zaszyfrowane dane nie przetrwają restartu) |
| `ASI_BIND` | `0.0.0.0:8080` | adres nasłuchu |
| `ASI_COOKIE_SECURE` | `false` | atrybut `Secure` cookie (włącz za HTTPS) |
| `ASI_SESSION_TTL_HOURS` | `12` | czas życia sesji |
| `ASI_SCAN_CONFIG` | — (wartości domyślne) | plik TOML skanu, przykład: `config/scan.toml`; błąd w pliku blokuje skany (409) i harmonogram |
| `ASI_SIGNATURES_DIR` | `signatures` | katalog wbudowanych sygnatur YAML |
| `ASI_DD_URL`, `ASI_DD_TOKEN`, `ASI_DD_PRODUCT` | — | DefectDojo (wszystkie trzy albo brak integracji); engagement `ASI <ip>` per IP w produkcie; wysyłka automatyczna po decyzji o CVE (info z CVE po sprawdzeniu albo samo info), błąd tylko w logu |
| `ASI_NVD_API_KEY` | — | opcjonalny klucz NVD API do sprawdzania podatności |
| `RUST_LOG` | `info,sqlx=warn` | poziom logów |

| Metoda | Ścieżka | Uprawnienie | Opis |
|---|---|---|---|
| GET | `/api/health` | — | 200 lub 503, gdy baza niedostępna (healthcheck) |
| POST | `/api/v1/auth/login` | — | `{username, password}` → profil + cookie `asi_session`; 401 błędne dane, 429 po 5 błędach / 15 min |
| POST | `/api/v1/auth/logout` | — | zawsze 204 i czyszczenie cookie |
| GET | `/api/v1/auth/config` | — | `{session_ttl_hours}` do komunikatu o ciasteczkach |
| GET | `/api/v1/me` | zalogowany | `{id, username, roles[], permissions[]}` |
| GET | `/api/v1/admin/ping` | `admin.users` | endpoint kontrolny macierzy ról (403 dla pozostałych ról) |
| GET | `/api/v1/targets` | `read` | lista celów (notatka odszyfrowana) |
| POST | `/api/v1/targets` | `targets.create` | `{text?, targets?: [{value, tags, note}]}` → raport |
| POST | `/api/v1/targets/import?format=csv,json,text&dry_run=` | `targets.create` | treść pliku → `{rows, accepted, duplicates, rejected[{row, value}], dry_run}` |
| PATCH / DELETE | `/api/v1/targets/{id}` | `targets.update` / `targets.delete` | `{tags?, note?, excluded?}` (pusty `note` usuwa notatkę) |
| GET / POST | `/api/v1/admin/users` | `admin.users` | lista kont; `{username, password, role}` (hasło ≥ 10 znaków, 409 przy zajętej nazwie) |
| PATCH / DELETE | `/api/v1/admin/users/{id}` | `admin.users` | `{role?, password?, disabled?}`; zmiana hasła i wyłączenie kończą sesje; 409 dla ostatniego aktywnego admina |
| GET | `/api/v1/admin/audit?limit=&before=` | `admin.audit` | dziennik od najnowszych (limit ≤ 500, `before` = id) |
| POST | `/api/v1/runs` | `scans.run` | start skanu, opcjonalne body `{target_ids: [uuid]}` (tylko te cele; wykluczone pomijane) → 202 `{run_id}`; 400: pusta lista, nieznany cel lub błędne body; 409: trwa skan, poza oknem, błędna konfiguracja, brak celów |
| GET | `/api/v1/runs`, `/api/v1/runs/{id}` | `read` | status (`running`/`done`/`partial`/`failed`/`cancelled`), powód, pokrycie, czasy |
| POST | `/api/v1/runs/{id}/cancel` | `scans.run` | przerywa trwający przebieg (wynik nie jest publikowany) |
| GET | `/api/v1/runs/{id}/report.pdf` | `export` | raport PDF przebiegu do pobrania (A4 poziomo, czcionka Monoid MIT); 404 nieznany, 409 przebieg trwa lub inny eksport w toku |
| GET | `/api/v1/runs/{id}/observations?limit=&offset=&ip=` | `read` | `{total, items}`: usługi z HTTP, TLS, technologiami i korektami; ciasteczka tylko nazwa + atrybuty |
| GET | `/api/v1/runs/{id}/changes?limit=&offset=&kind=` | `read` | `{total, items}` (new, gone, changed, host_inactive, host_returned) |
| GET | `/api/v1/runs/{id}/export?format=json,csv&profile=safe,raw` | `export` | eksport z korektami i `raw_*`; CSV domyślnie bezpieczny dla arkuszy |
| POST | `/api/v1/results/import?format=json,csv` | `targets.create` | import wyników (format eksportu) jako przebieg `import` |
| GET | `/api/v1/dashboard` | `read` | liczniki, technologie, ciekawe znaleziska, ostatnie zmiany (bez deszyfrowania) |
| GET | `/api/v1/observations/{id}/secrets` | `results.reveal` (admin) | pełne wartości ciasteczek i nagłówków; wpis audytu |
| PUT / DELETE | `/api/v1/overrides` | `data.update` | PUT `{key: "ip:port/proto", field, value, reason}`, DELETE `?key=&field=`; pola product, version, service, status, severity, owner, note |
| GET | `/api/v1/overrides?key=` | `read` | historia korekt (autor, powód, czas, wycofanie) |
| GET / POST | `/api/v1/signatures` | `read` / `signatures.create` | wbudowane + własne; `{yaml}` z walidacją ścieżek i regexów |
| PUT / DELETE | `/api/v1/signatures/{slug}` | `signatures.update` / `signatures.delete` | nowa wersja / wyłączenie |
| POST | `/api/v1/runs/{id}/defectdojo` | `integrations.export` | Generic Findings Import do DefectDojo (bez wartości ciasteczek, bez `false_positive`) |

Cookie `asi_session`: `HttpOnly; SameSite=Strict; Path=/`, w bazie tylko SHA-256 tokenu.
Sesja jest ważna, dopóki zgadza się wersja poświadczeń użytkownika (zmiana hasła lub wyłączenie
konta unieważnia wszystkie sesje). Frontend powinien wołać API z tego samego originu (proxy `/api`).

## Skaner

- **Zakres:** każde połączenie HTTP (pierwsze żądanie, przekierowanie, ścieżka z sygnatury) jest sprawdzane:
  schemat `http`/`https`, host z celów (IP/CIDR, domena-cel, adres rozwiązanej domeny), port z `ports` w konfiguracji
  albo wykryty jako otwarty w tym przebiegu. Przekierowania poza zakres są zapisywane jako zablokowane.
- **Zasoby:** odpowiedzi czytane strumieniowo do 256 KiB, sondy pod semaforem (`http_concurrency`), treść stron
  nie trafia do bazy; tempo nmap = `global_max_rate / concurrency` na proces.
- **Termin:** w oknie czasowym jeden termin obejmuje nmap, sondy HTTP i ponowne pomiary; niewykonana praca trafia
  do zaległości (`scan_chunks`) i jest wznawiana na początku następnego przebiegu (po ponownym sprawdzeniu celów).
- **Status:** `done` = cała praca wykonana (także bez odpowiedzi hostów), `partial` = zaległe/nieudane podgrupy,
  `failed` = żadna podgrupa się nie udała (np. brak nmap), `cancelled` = anulowano.
- **Wiele procesów:** jeden trwający skan na bazę (rezerwacja z dzierżawą odnawianą co 10 s, wygasa po 60 s);
  wynik publikowany w jednej transakcji tylko przez właściciela dzierżawy.

## Ochrona wyników

Wartości ciasteczek, nagłówki i bannery są w bazie tylko zaszyfrowane (`observations.data_enc`,
`http_info.cookies_enc`). API, eksport i DefectDojo pokazują ciasteczka jako nazwę i atrybuty, a wartości
nagłówków `authorization`, `cookie`, `x-api-key` itp. (oraz nazw z `token`/`secret`/`session`) jako `[redacted]`.
Pełne wartości: tylko `GET /observations/{id}/secrets` z uprawnieniem `results.reveal` (admin), z wpisem audytu.

## Import CSV

Dwa formaty z nagłówkiem: własny `target,tags,note` (tagi oddzielone `;`) oraz format organizatora. W drugim formacie kolumna `ip_address` jest celem, a `subnet_cidr`, `network_zone`
i `hostname` stają się tagami `subnet:…`, `zone:…`, `host:…` — podsieć nie jest rozwijana. Ponowny import
nie nadpisuje istniejących celów ani ich edycji (liczone jako duplikaty).

## Licencje zależności

Sprawdzone `cargo metadata` dla całego drzewa (stan z tej zmiany): wszystkie zależności mają
licencje MIT, Apache-2.0, BSD-2/3-Clause, Zlib, Unlicense, BSL-1.0 lub Unicode-3.0. Jedyna pozycja
z LGPL ma licencję alternatywną `MIT OR Apache-2.0 OR LGPL-2.1-or-later` (używamy MIT/Apache).
Brak zależności wyłącznie na GPL.
