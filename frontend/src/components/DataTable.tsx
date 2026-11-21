import { useState, type ReactNode } from "react";
import { BTN_SECONDARY } from "../utils";

export interface Column<T> {
  /** Pusty nagłówek oznacza kolumnę z przyciskami akcji (czytnik ekranu dostaje "Akcje"). */
  header: string;
  render: (row: T) => ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  emptyText?: string;
  /** Tekst wiersza do filtrowania. Gdy podany, nad tabelą pojawia się pole wyszukiwania. */
  filterBy?: (row: T) => string;
  /** Nazwa tabeli dla czytników ekranu, np. "Lista celów". */
  label?: string;
}

// Przy >10 000 celów renderowanie wszystkiego naraz blokuje przeglądarkę.
const PAGE_SIZE = 200;
// Pole filtra przy kilku wierszach to tylko szum.
const FILTER_FROM = 10;

export function DataTable<T>({ columns, rows, rowKey, emptyText = "Brak danych", filterBy, label }: DataTableProps<T>) {
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(PAGE_SIZE);

  const needle = query.trim().toLowerCase();
  const filtered = filterBy && needle ? rows.filter((row) => filterBy(row).toLowerCase().includes(needle)) : rows;
  const visible = filtered.slice(0, limit);

  return (
    <>
      {filterBy && rows.length > FILTER_FROM && (
        <div className="my-2 flex flex-wrap items-center gap-2">
          <input
            type="search"
            aria-label={label ? `Filtruj: ${label}` : "Filtruj"}
            placeholder="Filtruj..."
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setLimit(PAGE_SIZE);
            }}
          />
          <span className="text-muted" role="status">
            {needle ? `Pasuje ${filtered.length} z ${rows.length}` : `${rows.length} pozycji`}
          </span>
        </div>
      )}

      {filtered.length === 0 ? (
        <p className="my-3.5 text-muted">{needle ? "Brak wyników dla filtra" : emptyText}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full" aria-label={label}>
            <thead>
              <tr>
                {columns.map((column) => (
                  <th key={column.header} scope="col">
                    {column.header || <span className="sr-only">Akcje</span>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map((row, index) => (
                <tr key={rowKey(row, index)}>
                  {columns.map((column) => (
                    <td key={column.header}>{column.render(row)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {filtered.length > limit && (
        <div className="my-2 flex flex-wrap items-center gap-2">
          <span className="text-muted">
            Pokazano {visible.length} z {filtered.length}
          </span>
          <button className={BTN_SECONDARY} onClick={() => setLimit(limit + PAGE_SIZE)}>
            Pokaż kolejne {Math.min(PAGE_SIZE, filtered.length - limit)}
          </button>
        </div>
      )}
    </>
  );
}
