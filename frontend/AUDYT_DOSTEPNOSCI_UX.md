# Audyt dostępności i UI/UX ASI

Data: 2026-11-21 · Zakres: `frontend/src` (React + Tailwind) · Odniesienie: WCAG 2.2 AA oraz „AGH – Pełna treść zadania konkursowego.pdf”.
Stan po scaleniu z `main` (nowy backend `backend/` na PostgreSQL, API `/api/v1`). Poprawki dostępności i UX są przeniesione na frontend API v1. Funkcje, których API v1 nie udostępnia, są wypisane w sekcji 4 jako braki.

## 1. Podsumowanie

| Obszar | Przed | Po |
|---|---|---|
| Etykiety pól formularzy | logowanie, cele, sygnatury, użytkownicy: tylko placeholdery albo brak | wszystkie kontrolki mają nazwę dostępną (sprawdzone skryptem na 5 stronach: 0 bez nazwy) |
| Struktura nagłówków | brak `h1`, karty od `h3` | `h1` na każdej stronie, karty `h2`, szczegóły `h3/h4` |
| Kontrast | zielony 3,3:1 i pomarańczowy 3,2:1 (jasny motyw), czerwony 3,5:1 (ciemny), obramowania pól 1,2:1 | wszystkie teksty statusów ≥ 4,5:1, obramowania pól ≥ 3:1 w obu motywach |
| Komunikaty | nieogłaszane przez czytniki ekranu | `role="status"` / `role="alert"` |
| Nawigacja klawiaturą | brak skip linku, brak `aria-current`, fokus zostaje na przycisku | skip link, `aria-current="page"`, po zmianie widoku fokus trafia na `h1`, wyraźny `:focus-visible` |
| Zgodność ze specyfikacją | nagłówki, przekierowania i dowody detekcji niewidoczne w UI | panel „Szczegóły” usługi; braki API v1 w sekcji 4 |

## 2. Dostępność (WCAG 2.2 AA): znalezione problemy i poprawki

| # | Problem | Kryterium | Poprawka | Plik |
|---|---|---|---|---|
| A1 | Pola logowania tylko z placeholderem | 1.3.1, 3.3.2 | `<label>`, `required`, `aria-invalid` | `pages/LoginPage.tsx` |
| A2 | Błąd logowania nieogłaszany, komunikat „Wymagane zalogowanie” przy złym haśle | 4.1.3, 3.3.1 | `role="alert"`, komunikat „Nieprawidłowy login lub hasło”, stan „Logowanie...” | `pages/LoginPage.tsx` |
| A3 | Kolory statusów poniżej 4,5:1 | 1.4.3 | nowe tokeny `green/orange/red` dla obu motywów | `styles.css` |
| A4 | Obramowanie pól 1,24:1 | 1.4.11 | token `--color-field` (3,5–4,3:1) | `styles.css` |
| A5 | Brak widocznego fokusu dla własnych stylów | 2.4.7 | globalny `:focus-visible` z obrysem w kolorze akcentu | `styles.css` |
| A6 | Brak `h1`, nagłówki kart od `h3` | 1.3.1, 2.4.6 | `h1` z nazwą strony, karty `h2` + `aria-labelledby` | `App.tsx`, `components/Card.tsx` |
| A7 | Brak pominięcia nawigacji, landmarków nazwanych | 2.4.1 | skip link „Przejdź do treści”, `nav aria-label`, `main id` | `App.tsx` |
| A8 | Aktywna zakładka rozróżniana tylko kolorem | 1.4.1, 4.1.2 | `aria-current="page"` + pogrubienie | `App.tsx` |
| A9 | Po zmianie widoku czytnik nic nie ogłasza | 2.4.3 | fokus na `h1`, tytuł karty przeglądarki `Strona · ASI` | `App.tsx` |
| A10 | Komunikaty sukcesu/błędu nieogłaszane | 4.1.3, 2.2.1 | powiadomienia (toasty) Sonner z shadcn/ui: region `aria-live` „Powiadomienia”, skrót Alt+T, przycisk zamknięcia, błędy wiszą 10 s, najechanie wstrzymuje licznik, bez animacji przy `prefers-reduced-motion`; błędy ładowania i logowania zostają przy treści z `role="alert"` | `components/ui/sonner.tsx`, `hooks.ts` |
| A11 | Pola edycji w tabeli celów (tagi, notatka, checkbox) bez nazw | 4.1.2 | `aria-label` z wartością celu, np. „Tagi celu 10.0.0.1” | `pages/TargetsPage.tsx` |
| A12 | Przyciski w wierszach „Usuń”, „JSON”, „Zmiany” niejednoznaczne poza kontekstem | 2.4.6, 2.4.9 | `aria-label` z identyfikatorem wiersza, np. „Eksport skanu 2026-11-21 12:00 do CSV” | strony |
| A13 | Pusty nagłówek kolumny akcji, `th` bez `scope` | 1.3.1 | `scope="col"`, ukryty tekst „Akcje”, `aria-label` tabeli | `components/DataTable.tsx` |
| A14 | Pole wyboru pliku bez etykiety, brak stanu wysyłania | 4.1.2, 4.1.3 | `aria-label`, `aria-busy`, „Wysyłanie...” | `components/FilePicker.tsx` |
| A15 | Pola tekstowe sygnatur i celów bez etykiet | 1.3.1 | `<label>` + `aria-describedby` z podpowiedzią | `pages/SignaturesPage.tsx`, `pages/TargetsPage.tsx` |
| A16 | Role w formularzu i tabeli użytkowników jako kody (`viewer`) | 3.3.2 | nazwy ról z treści zadania; pola mają `aria-label` (wersja z `main`) | `pages/UsersPage.tsx` |
| A17 | Dowody detekcji tylko w atrybucie `title` (niedostępne z klawiatury i dotyku) | 1.3.1, 2.1.1 | dowody widoczne w szczegółach usługi | `components/ObservationTable.tsx` |
| A18 | Szczegóły skanu otwierały się poniżej, bez informacji dla użytkownika | 2.4.3 | przewinięcie i fokus na nagłówek otwartego panelu | `pages/RunsPage.tsx`, `components/ObservationTable.tsx` |
| A19 | Wykres zmian w czasie musiałby być dostępny bez wzroku | 1.1.1 | tabela z liczbami, pasek tylko ilustracyjny (`aria-hidden`) | `pages/DashboardPage.tsx` |

## 3. UI/UX: znalezione problemy i poprawki

| # | Problem | Poprawka |
|---|---|---|
| U1 | Role i statusy wyświetlane po angielsku (`viewer`, `partial`) | nazwy ról zgodne z pkt 13 zadania („Odczyt”, „Modyfikacja i odczyt”, „Dodawanie, usuwanie, modyfikacja”, „Administracja”), polskie statusy przebiegów („w kolejce”, „zakończony”, „częściowy”, „anulowany”) |
| U2 | Czas skanu w sekundach (`28800.0`) | format „8 h 0 min 0 s” na liście skanów i na dashboardzie |
| U4 | Brak odświeżania w trakcie skanu („Odśwież listę, aby zobaczyć postęp”) | automatyczne odświeżanie co 5 s, gdy trwa skan (dashboard i skany), przycisk „Uruchom skan” zablokowany w trakcie skanu |
| U5 | >10 000 celów renderowanych naraz (zawieszenie przeglądarki) | tabele pokazują po 200 wierszy z przyciskiem „Pokaż kolejne”, filtr tekstowy dla dłuższych tabel |
| U6 | Edycja tagów/notatki celu zapisywała się tylko po opuszczeniu pola | dodany zapis klawiszem Enter, podpowiedź w `title` |
| U8 | Moduł sygnatur bez informacji o bezpiecznym użyciu | podpowiedź pod polem YAML (zgodnie z sekcją o bezpiecznych sygnaturach) |
| U9 | Słabo czytelny dashboard (wymóg pkt 15 i kryterium 10) | sekcja „Podsumowanie”, opis znalezisk, polskie nazwy kategorii (panel administracyjny, staging, IoT), nowa sekcja „Zmiany w czasie” |
| U10 | Na telefonie liczniki dashboardu w jednej kolumnie | węższe kafle (2 kolumny przy 375 px), brak poziomego przewijania strony |

## 4. Zgodność z treścią zadania (frontend na API v1)

✅ jest · 🆕 dodane w tym audycie · ⚠️ częściowo · ❌ brak w API v1, wymaga backendu

| Wymaganie (PDF) | Status | Uwagi |
|---|---|---|
| 1. Wczytanie IP, CIDR, domen | ✅ | ręcznie + plik CSV/JSON/TXT, podgląd importu |
| 2. Skan discovery, czas trwania | ✅ 🆕 | czas w czytelnym formacie, anulowanie skanu |
| 2. Podział na podgrupy | ⚠️ | robi backend; UI pokazuje pokrycie (zaplanowane/zeskanowane/zaległe) |
| 3–4. Aktywne hosty, usługi | ✅ | |
| 5. Tytuł, kod HTTP, nagłówki, ciasteczka, przekierowania | ✅ 🆕 | panel „Szczegóły” usługi (nagłówki, przekierowania, zablokowane przekierowania, ciasteczka z atrybutami) |
| 5. Certyfikat TLS | ✅ 🆕 | API v1 zwraca `http.tls`; pokazany w szczegółach usługi (podmiot, wystawca, ważność, SHA-256) |
| 6–7. CMS, framework, IoT, staging, panel admina | ✅ 🆕 | polskie kategorie, dowody detekcji w szczegółach |
| 8. Porównanie kolejnych przebiegów | ✅ | „Zmiany” przy przebiegu |
| Porównanie dwóch dowolnych skanów | ❌ | brak endpointu porównania w API v1 |
| 9. Nowe, znikające, zmienione usługi | ✅ | |
| 10. Własne sygnatury | ✅ | dodawanie, edycja (nowa wersja), wyłączanie |
| 11. Formularz: ręcznie + CSV/JSON | ✅ | |
| 12–13. RBAC i 4 role | ✅ 🆕 | role nazwane jak w zadaniu |
| 14. Edycja niezależnie od skanu | ✅ 🆕 | cele (tagi, notatka, wykluczenie); korekty wyników przez `/overrides`: status i notatka w tabeli, priorytet (`Info`–`Critical`, trafia do DefectDojo), serwis, produkt, wersja i właściciel w szczegółach usługi. Korekty są w eksporcie (`asi-core/src/export.rs`) |
| 15. Czytelny interfejs, dashboard | ✅ 🆕 | sekcje 2 i 3 |
| Konfiguracja skanu: okno czasowe, częstotliwość | ✅ | plik `backend/config/scan.toml`; zmiana z UI nie jest wymagana, brak endpointu |
| Ograniczanie tempa | ✅ | `global_max_rate` w `scan.toml` |
| Edycja danych skanów i wyników | ✅ | korekty wyników jw.; edycja metadanych przebiegu (np. notatki) poza zakresem, brak endpointu |
| Eksport JSON/CSV | ✅ | |
| Mile widziane: różnice zależne od pory dnia | 🆕 ⚠️ | średnie hostów/usług wg pory startu skanu (z `coverage`); agregat per skan |
| Mile widziane: ocena „ciekawości” | 🆕 | kolumna „Ocena” 0–100 (kategoria × pewność + priorytet z korekty), sortowanie w obrębie strony wyników |
| Mile widziane: grupowanie podobnych usług | 🆕 | przełącznik w tabeli usług (w obrębie strony wyników) |
| Mile widziane: tagi | ✅ | cele |
| Mile widziane: eksport wybranych obserwacji do DefectDojo | ❌ | API v1 wysyła cały przebieg |
| Mile widziane: wizualizacja zmian w czasie | 🆕 | „Zmiany w czasie” na dashboardzie (hosty, usługi, czas) |

Wersja tych braków dla starego backendu (`src/`, SQLite) jest w historii: commity „feat(backend): scan settings API…” i „feat(frontend): accessibility audit fixes…” na gałęzi `frontend`. Po scaleniu `main` buduje wyłącznie `backend/`, więc trzeba je zaimplementować w nowym backendzie.

## 5. Weryfikacja

- `npm run build` (tsc + vite) po scaleniu: bez błędów.
- Przeglądarka (Vite, odpowiedzi API v1 podstawione w przeglądarce): sekcja w raporcie scalenia.

Nie sprawdzono: frontendu z nowym backendem na prawdziwej bazie, testu z czytnikiem ekranu, pełnego skanu axe.

## 6. Pozostałe uwagi (bez zmian)

- Formularz nowego użytkownika czyści pola także wtedy, gdy backend odrzuci utworzenie konta (np. zajęty login).
- Reset hasła używa `prompt()`, który pokazuje hasło jawnym tekstem (wersja z `main`).
- Usunięcie elementu korzysta z `confirm()`, co jest dostępne, ale nie da się go ostylować.
