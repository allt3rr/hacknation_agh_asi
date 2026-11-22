import { useState } from "react";
import type { Target } from "../types";
import { BTN_SECONDARY } from "../utils";
import { Command, CommandEmpty, CommandInput, CommandItem, CommandList } from "./ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "./ui/popover";

/** Wszystkie tagi z listy celów, posortowane, bez powtórzeń. */
export function collectTags(targets: Target[]): string[] {
  return [...new Set(targets.flatMap((t) => t.tags))].sort((a, b) => a.localeCompare(b));
}

interface TagComboboxProps {
  tags: string[];
  /** Wybrany tag (tryb filtru); w trybie dodawania zawsze null. */
  value: string | null;
  onSelect: (tag: string | null) => void;
  /** Dostępna nazwa przycisku, np. "Filtr: tag". */
  label: string;
  /** Tekst przycisku bez wybranego tagu. */
  placeholder: string;
  /** Pozycja czyszcząca wybór (tryb filtru). */
  clearLabel?: string;
  /** Pozwala utworzyć tag z wpisanego tekstu (tryb dodawania). */
  allowCreate?: boolean;
}

/** Combobox shadcn/ui (Popover + Command): wybór tagu z wyszukiwaniem w popupie. */
export function TagCombobox({ tags, value, onSelect, label, placeholder, clearLabel, allowCreate }: TagComboboxProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const typed = search.trim();
  const choose = (tag: string | null) => {
    onSelect(tag);
    setOpen(false);
    setSearch("");
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button type="button" role="combobox" aria-expanded={open} aria-label={label} className={`${BTN_SECONDARY} ${value ? "border-accent text-accent" : ""}`}>
          <span className="mono">{value ?? placeholder}</span> <span aria-hidden className="text-[10px] opacity-60">▼</span>
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-64">
        <Command>
          <CommandInput placeholder={allowCreate ? "szukaj lub wpisz nowy tag" : "szukaj tagu"} value={search} onValueChange={setSearch} maxLength={64} aria-label={label} />
          <CommandList>
            <CommandEmpty>brak tagów</CommandEmpty>
            {clearLabel && value && (
              <CommandItem value={`\u0000${clearLabel}`} onSelect={() => choose(null)}>
                {clearLabel}
              </CommandItem>
            )}
            {tags.map((tag) => (
              <CommandItem key={tag} value={tag} onSelect={() => choose(tag)} className="mono">
                {tag}
              </CommandItem>
            ))}
            {allowCreate && typed && !tags.includes(typed) && (
              <CommandItem value={`Dodaj tag ${typed}`} onSelect={() => choose(typed)}>
                Dodaj tag „<span className="mono">{typed}</span>”
              </CommandItem>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
