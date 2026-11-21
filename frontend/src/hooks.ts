import { useCallback, useEffect, useState } from "react";
import { errorMessage } from "./utils";

/**
 * Pobiera dane przy montowaniu komponentu i udostępnia `reload`.
 * `load` musi mieć stabilną referencję (np. funkcja z obiektu `api`).
 */
export function useApiData<T>(load: () => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setData(await load());
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, [load]);

  useEffect(() => {
    reload();
  }, [reload]);

  return { data, error, reload };
}

export interface Notice {
  kind: "info" | "error";
  text: string;
}

/** Komunikat dla użytkownika po akcji (sukces lub błąd). */
export function useNotice() {
  const [notice, setNotice] = useState<Notice | null>(null);

  const info = useCallback((text: string) => setNotice({ kind: "info", text }), []);
  const error = useCallback((e: unknown) => setNotice({ kind: "error", text: errorMessage(e) }), []);

  /** Wykonuje akcję i w razie wyjątku pokazuje błąd. */
  const run = useCallback(
    async (action: () => Promise<void>) => {
      try {
        await action();
      } catch (e) {
        error(e);
      }
    },
    [error],
  );

  return { notice, info, error, run };
}
