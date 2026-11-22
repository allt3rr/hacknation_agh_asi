// Komponent Command z shadcn/ui (https://ui.shadcn.com/docs/components/command) na cmdk, okrojony jak select.tsx.

import type { ComponentProps } from "react";
import { Command as CommandPrimitive } from "cmdk";

export function Command({ className = "", ...props }: ComponentProps<typeof CommandPrimitive>) {
  return <CommandPrimitive className={`flex flex-col text-fg ${className}`} {...props} />;
}

export function CommandInput({ className = "", ...props }: ComponentProps<typeof CommandPrimitive.Input>) {
  return <CommandPrimitive.Input className={`mb-1 w-full ${className}`} {...props} />;
}

export function CommandList({ className = "", ...props }: ComponentProps<typeof CommandPrimitive.List>) {
  return <CommandPrimitive.List className={`max-h-60 overflow-x-hidden overflow-y-auto ${className}`} {...props} />;
}

export function CommandEmpty(props: ComponentProps<typeof CommandPrimitive.Empty>) {
  return <CommandPrimitive.Empty className="px-2 py-1 text-muted" {...props} />;
}

export function CommandItem({ className = "", ...props }: ComponentProps<typeof CommandPrimitive.Item>) {
  return (
    <CommandPrimitive.Item
      className={`cursor-pointer truncate rounded px-2 py-1 outline-none select-none data-[disabled=true]:opacity-50 data-[selected=true]:bg-surface-2 data-[selected=true]:text-accent ${className}`}
      {...props}
    />
  );
}
