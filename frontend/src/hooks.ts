import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
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

// Błędy wiszą dłużej i można je zamknąć ręcznie (WCAG 2.2.1); najechanie kursorem wstrzymuje licznik.
const ERROR_DURATION_MS = 10_000;

/** Powiadomienie po akcji (sukces lub błąd) jako toast Sonner z shadcn/ui. */
export function useNotice() {
  const info = useCallback((text: string) => {
    toast.success(text);
  }, []);
  const error = useCallback((e: unknown) => {
    toast.error(errorMessage(e), { duration: ERROR_DURATION_MS });
  }, []);

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

  return { info, error, run };
}
