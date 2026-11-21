import { useState } from "react";

interface FilePickerProps {
  accept: string;
  buttonLabel: string;
  onSubmit: (file: File) => Promise<void>;
}

/** Wybór pliku z przyciskiem wysyłki. */
export function FilePicker({ accept, buttonLabel, onSubmit }: FilePickerProps) {
  const [file, setFile] = useState<File | null>(null);

  return (
    <span className="file-picker">
      <input type="file" accept={accept} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
      <button className="secondary" disabled={!file} onClick={() => file && onSubmit(file)}>
        {buttonLabel}
      </button>
    </span>
  );
}
