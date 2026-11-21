import { useState } from "react";
import { BTN_SECONDARY } from "../utils";

interface FilePickerProps {
  accept: string;
  buttonLabel: string;
  onSubmit: (file: File) => Promise<void>;
}

/** Wybór pliku z przyciskiem wysyłki. */
export function FilePicker({ accept, buttonLabel, onSubmit }: FilePickerProps) {
  const [file, setFile] = useState<File | null>(null);

  return (
    <span>
      <input type="file" accept={accept} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
      <button className={BTN_SECONDARY} disabled={!file} onClick={() => file && onSubmit(file)}>
        {buttonLabel}
      </button>
    </span>
  );
}
