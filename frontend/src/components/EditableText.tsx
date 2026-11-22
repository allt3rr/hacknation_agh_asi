import { useState } from "react";

/** Pole tekstowe zapisywane po opuszczeniu (blur) lub Enter, tylko jeśli wartość się zmieniła. */
export function EditableText({ value, onSave, label }: { value: string; onSave: (value: string) => void; label: string }) {
  const [draft, setDraft] = useState(value);
  return (
    <input
      aria-label={label}
      title="Zapis po wyjściu z pola lub klawiszem Enter"
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      onKeyDown={(e) => e.key === "Enter" && e.currentTarget.blur()}
      onBlur={() => draft !== value && onSave(draft)}
    />
  );
}
