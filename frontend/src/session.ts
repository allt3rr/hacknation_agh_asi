// Przechowywanie sesji w sessionStorage (znika po zamknięciu karty).
// Dostęp do storage może rzucić wyjątek (np. tryb prywatny), dlatego każde wywołanie jest w try/catch.

import type { Session } from "./types";

const STORAGE_KEY = "asi.session";

export function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
}

export function saveSession(session: Session) {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  } catch {
    // sesja zadziała do odświeżenia strony
  }
}

export function clearSession() {
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // nic do zrobienia
  }
}
