// Komponent Sonner z shadcn/ui (https://ui.shadcn.com/docs/components/sonner), dopasowany do projektu:
// bez next-themes (motyw idzie za systemem, jak reszta aplikacji) i z tokenami kolorów z styles.css.
// Tekst zostaje w kolorze fg na tle surface (kontrast AA), status pokazuje kolorowa ikona i lewa krawędź.

import type { CSSProperties } from "react";
import { Toaster as Sonner, type ToasterProps } from "sonner";

export function Toaster(props: ToasterProps) {
  return (
    <Sonner
      theme="system"
      position="bottom-right"
      offset={{ bottom: 96 }}
      mobileOffset={{ bottom: 96 }}
      closeButton
      containerAriaLabel="Powiadomienia"
      className="toaster group"
      style={
        {
          "--normal-bg": "var(--color-surface)",
          "--normal-text": "var(--color-fg)",
          "--normal-border": "var(--color-line)",
        } as CSSProperties
      }
      toastOptions={{
        classNames: {
          toast: "!font-[inherit] !text-sm shadow-lg",
          success: "!border-l-4 !border-l-green [&_[data-icon]]:text-green",
          error: "!border-l-4 !border-l-red [&_[data-icon]]:text-red",
          closeButton: "!bg-surface !text-fg !border-line",
        },
      }}
      {...props}
    />
  );
}
