// Komponent Select z shadcn/ui (https://ui.shadcn.com/docs/components/select), okrojony do tego, czego używa
// projekt, i dopasowany do tokenów kolorów z styles.css (bez cn/lucide).

import type { ComponentProps } from "react";
import * as SelectPrimitive from "@radix-ui/react-select";

export const Select = SelectPrimitive.Root;
export const SelectValue = SelectPrimitive.Value;

export function SelectTrigger({ className = "", children, ...props }: ComponentProps<typeof SelectPrimitive.Trigger>) {
  return (
    <SelectPrimitive.Trigger
      className={`inline-flex items-center gap-1.5 border border-line bg-surface text-fg shadow-none hover:border-accent hover:text-accent data-[placeholder]:text-fg ${className}`}
      {...props}
    >
      {children}
      <SelectPrimitive.Icon aria-hidden className="text-[10px] opacity-60">
        ▼
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  );
}

export function SelectContent({ className = "", children, ...props }: ComponentProps<typeof SelectPrimitive.Content>) {
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        position="popper"
        sideOffset={4}
        className={`z-50 min-w-(--radix-select-trigger-width) overflow-hidden rounded border border-line bg-surface p-1 text-fg shadow-lg ${className}`}
        {...props}
      >
        <SelectPrimitive.Viewport>{children}</SelectPrimitive.Viewport>
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  );
}

export function SelectItem({ className = "", children, ...props }: ComponentProps<typeof SelectPrimitive.Item>) {
  return (
    <SelectPrimitive.Item
      className={`cursor-pointer rounded px-2 py-1 whitespace-nowrap outline-none select-none data-[disabled]:cursor-default data-[disabled]:opacity-50 data-[highlighted]:bg-surface-2 data-[highlighted]:text-accent ${className}`}
      {...props}
    >
      <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
    </SelectPrimitive.Item>
  );
}
