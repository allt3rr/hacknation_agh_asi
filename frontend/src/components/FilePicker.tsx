import { useState } from "react";
import { BTN_SECONDARY } from "../utils";

interface FilePickerProps {
  accept: string;
  /** Etykieta pola wyboru pliku, np. "Plik z celami". */
  label: string;
  buttonLabel: string;
  onSubmit: (file: File) => Promise<void>;
}

/** Wybór pliku z przyciskiem wysyłki. */
export function FilePicker({ accept, label, buttonLabel, onSubmit }: FilePickerProps) {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!file) return;
    setBusy(true);
    try {
      await onSubmit(file);
    } finally {
      setBusy(false);
    }
  };

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <input type="file" accept={accept} aria-label={label} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
      <button className={BTN_SECONDARY} disabled={!file || busy} aria-busy={busy} onClick={submit}>
        {busy ? "Wysyłanie..." : buttonLabel}
      </button>
    </span>
  );
}
