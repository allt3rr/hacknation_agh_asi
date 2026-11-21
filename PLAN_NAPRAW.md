# Plan napraw ASI

Plan obejmuje ustalenia z [audytu z 21 listopada 2026](AUDYT.md). Priorytet P0 oznacza blokadę użycia produkcyjnego. P1 obejmuje pozostałe poprawki potrzebne do wydania i odbioru projektu.

| Etap | Priorytet | Kiedy zacząć |
|---|---|---|
| 1. Zakres ruchu, okna i pamięć | P0 | Od razu |
| 2. Dostęp do danych, konta i sekrety | P0 | Równolegle z etapem 1 |
| 3. Wiarygodność wyników i praca wielu procesów | P0 | Statusy od razu. Migracje po decyzji o bazie |
| 4. Zależności i obraz | P0 dla wydania | Równolegle. Ponowić sprawdzenie na końcowym obrazie |
| 5. Funkcje konkursowe i zgodność danych | P1 | Po ustaleniu modelu danych oraz zasad udostępniania wyników |
| 6. Próba odbiorowa | P1 | Po połączeniu poprawek |

**Decyzja o bazie.** Bieżący kod i README używają SQLite, a wewnętrzny OpenSpec etapu 1 wymaga PostgreSQL 16. Opiekun projektu powinien rozstrzygnąć tę rozbieżność przed zmianą schematu. Proponowany wariant dla prototypu to SQLite i jawne uzgodnienie odstępstwa z właścicielem specyfikacji. Jeśli obowiązuje OpenSpec, etap 3 obejmie również migrację do PostgreSQL, obsługę `DATABASE_URL`, komendę `asi migrate` i sprawdzenie przeniesienia istniejących danych. Prace nad redakcją odpowiedzi, limitami HTTP i testami statusów można rozpocząć od razu.

## 1. Ograniczyć ruch i zużycie zasobów

- W `scanner/http.rs` sprawdzać wynikowy schemat, host i port przed każdym połączeniem, również po przekierowaniu i przy pobieraniu dodatkowej ścieżki. Przy zapisie i wczytywaniu sygnatur odrzucać ścieżki zmieniające origin. Walidacja musi obejmować również zapisane wcześniej sygnatury.
- Stosować limit 256 KiB podczas strumieniowego odczytu każdej odpowiedzi. Ograniczyć równocześnie trzymane treści i kolejkę pracy. Zmierzyć maksymalne użycie RAM przy skonfigurowanej współbieżności.
- Rozróżnić brak skonfigurowanych okien od konfiguracji błędnej. Dla aktywnej polityki okien wyznaczać jeden termin dla procesu nmap, HTTP i ponowień. Sprawdzić jego stosowanie w harmonogramie, API i CLI. Pozostałą pracę przekazać do mechanizmu wznowienia z etapu 3.

**Odbiór.** Użyć kontrolowanego zegara, atrap transportu i procesu. Rejestr połączeń zawiera wyłącznie dopuszczone adresy i porty. Po terminie aktywna sonda kończy się, a następna się nie rozpoczyna. Błędne okno blokuje start. Duża odpowiedź bez deklarowanej długości zostaje ucięta podczas odczytu, także dla dodatkowej ścieżki.

## 2. Chronić wyniki, poświadczenia i sesje

- Najpierw redagować wartości cookies na wyjściu API i eksportu dla wszystkich historycznych i nowych obserwacji. Zostawić nazwy i atrybuty potrzebne do fingerprintingu. Jeśli wymagany jest dostęp do wartości, zastosować odrębne uprawnienie i rejestrować użytkownika, zakres oraz czas dostępu. Sprawdzić również dashboard i raport do DefectDojo.
- Usunąć wypisywanie hasła administratora. Ujednolicić walidację haseł. Rozdzielić demonstracyjny sposób przechowywania klucza od produkcyjnego źródła sekretów. Dla istniejącej bazy najpierw sprawdzić odczyt kopii starym kluczem, następnie przenieść klucz lub przeprowadzić kontrolowane ponowne szyfrowanie. Jeśli hasło trafiło już do logów, przewidzieć jego zmianę i unieważnienie sesji.
- Ograniczyć próby logowania i liczbę równoległych weryfikacji Argon2, przenieść obliczenia poza wątki obsługi żądań i wyrównać obsługę nieznanego konta. Powiązać wystawienie sesji z aktualną wersją poświadczeń. Aktualizację hasła i unieważnienie sesji wykonać atomowo. Chronić ostatnie konto administracyjne także przy równoczesnych zmianach.
- Pokazywać potwierdzenie wylogowania po odpowiedzi serwera. Przy błędzie umożliwić ponowienie. Czas w komunikacie o cookie pobierać z konfiguracji backendu. Sprawdzić ustawienie Secure dla wdrożenia HTTPS oraz wymagania projektu dotyczące ochrony żądań zmieniających dane.

**Odbiór.** Sztuczna wartość testowa zapisana w starej obserwacji nie pojawia się w odpowiedzi dla viewer ani w zwykłym eksporcie. Uprawnione odsłonięcie zostawia wpis audytowy bez sekretu. Przy równoczesnym logowaniu i resecie po zakończeniu resetu starym hasłem nie da się uzyskać ważnej sesji. Błąd wylogowania jest widoczny, a po zmianie TTL komunikat pokazuje nową wartość. Sprawdzić start aplikacji i odtworzenie kopii przy produkcyjnym sposobie dostarczania klucza.

## 3. Zagwarantować poprawny status, wznowienie i zapis

- Najpierw naprawić wyliczanie statusu w `pipeline.rs`. Awaria wszystkich podgrup daje `failed`, częściowe pokrycie daje `partial`, a `completed` oznacza wykonanie całej zaplanowanej pracy. Poprawnie wykonany pomiar bez odpowiedzi hostów może być zakończony sukcesem. Pokazać w UI pokrycie i powód przerwania.
- Rezerwować przebieg atomowo we wspólnej bazie przed potwierdzeniem startu. Usunąć bezwarunkowe oznaczanie aktywnych przebiegów jako przerwanych przy inicjalizacji CLI. Odzyskiwać osierocony przebieg po potwierdzeniu wygaśnięcia rezerwacji. Poprzedni właściciel po utracie rezerwacji ma przerwać pracę i utracić prawo publikacji wyniku.
- Utrwalać niedokończone etapy i błędne podgrupy z kontrolą ponowień. Przed wznowieniem ponownie sprawdzić aktualny zakres. Wyznaczać termin i zaległości harmonogramu na podstawie skanów. Import ma własną historię. Publikować obserwacje, zmiany, stan hostów i końcowy status spójnie, a przerwaną publikację bezpiecznie ponawiać.

**Odbiór.** Dwa procesy na jednej testowej bazie mogą uzyskać tylko jedną rezerwację. Import celów podczas skanu zachowuje status aktywnego przebiegu. Restart między etapami i import wyników między oknami zachowują zaległości. Symulowany błąd zapisu nie zmienia opublikowanej bazy odniesienia. Ponowienie nie dubluje obserwacji ani zdarzeń.

## 4. Ustabilizować zależności i wydanie

- Dobrać wspierane, zgodne wersje Vite i esbuild oraz poprawione wersje quick-xml i biblioteki SQLite używanej przez SQLx. Zweryfikować aktywne zależności osobno dla platformy docelowej. Udokumentować ocenę wpisu RSA oraz sposób utrzymania lub zastąpienia chrono i unsafe-libyaml.
- Wersjonować Cargo.lock aplikacji, budować z `--locked`, zachować spójność npm lockfile i przejść na wspieraną bazę obrazu. Zweryfikować końcowy obraz po identyfikatorze oraz obrazy profilu laboratoryjnego przed odbiorem.

**Odbiór.** Czysty checkout przechodzi instalację z lockfile, testy Rust, typecheck i build frontendu. Raport dla końcowego obrazu i raport zależności wskazują, które wpisy usunięto, które są osiągalne i kto odpowiada za ewentualne pozostałe ryzyko.

## 5. Domknąć wymagania funkcjonalne

| Praca | Warunek odbioru |
|---|---|
| Powiązać istniejący klucz usługi i adnotacje z trwałymi korektami, historią autora oraz widokiem i eksportem. Zachować surowy pomiar dla porównań. | Analityk koryguje wynik, viewer odczytuje go po kolejnym przebiegu, eksport uwzględnia korektę, a historia pomiarów pozostaje dostępna. |
| Obsłużyć nagłówki dołączonego zbioru CSV. W importerze celów traktować adres z wiersza jako cel, a szerszą podsieć jako metadane, o ile użytkownik jawnie nie importuje zakresów. Doprecyzować format wymiany wyników i zabezpieczyć eksport przeznaczony do arkuszy. | Plik 10k przechodzi przez odpowiedni importer z raportem wierszy, odrzuceń i duplikatów. Własny CSV zachowuje reklamowane pola HTTP i technologie po ponownym imporcie. Arkusz wyświetla nieufny tekst jako dane. |
| Zachować powiązanie domeny z adresem i przebiegiem podczas rozliczania braków odpowiedzi. Zweryfikować przypisanie wyniku HTTP do właściwej domeny przy współdzielonym IP. | Kontrolowane wyniki dla domeny pokazują brak odpowiedzi, przekroczenie progu i powrót. Zmiana adresu domeny nie oznacza automatycznego zaniku innej usługi. |
| Agregować liczniki dashboardu bez deszyfrowania całego przebiegu. Stronicować szczegóły i pokazywać liczbę wszystkich zmian. | Przy 201 zmianach dashboard pokazuje 201, nawet gdy pierwsza strona zawiera mniej rekordów. Szczytowe użycie pamięci jest mierzone na dużym zbiorze. |

## 6. Odbiór i decyzja o wydaniu

1. Uruchomić testy regresji z etapów 1–5 na nowej bazie oraz na kopii sprzed migracji. Sprawdzić możliwość odtworzenia poprzedniej wersji wraz z danymi i kluczem.
2. Przetworzyć kontrolowany zbiór reprezentujący ponad 10 000 unikatowych adresów. Zapisać liczbę unikatowych adresów, czas, szczytowe RAM i pokrycie. Samo policzenie wierszy CSV nie dowodzi skali.
3. Na środowisku odbiorowym organizatora wykonać dwa uzgodnione pomiary w dopuszczonym zakresie i oknie. Porównać oczekiwane zmiany, trwałość korekty, eksport i działanie czterech ról. Potwierdzić przyjęcie raportu przez referencyjne DefectDojo. Dostęp do tej instancji jest zależnością próby integracyjnej.
4. Uzgodnić README, OpenSpec i instrukcję wdrożenia z przyjętymi decyzjami. Przygotować prezentację konkursową do 10 slajdów z demonstracją wyników. Do decyzji o wydaniu dołączyć dowody odbioru P0, wynik próby konkursowej i jawnie wskazane pozostałe ograniczenia.
