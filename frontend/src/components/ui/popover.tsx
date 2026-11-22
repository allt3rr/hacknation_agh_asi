// Komponent Popover z shadcn/ui (https://ui.shadcn.com/docs/components/popover), okrojony jak select.tsx.

import type { ComponentProps } from "react";
import * as PopoverPrimitive from "@radix-ui/react-popover";

export const Popover = PopoverPrimitive.Root;
export const PopoverTrigger = PopoverPrimitive.Trigger;

export function PopoverContent({ className = "", align = "start", sideOffset = 4, ...props }: ComponentProps<typeof PopoverPrimitive.Content>) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        align={align}
        sideOffset={sideOffset}
        className={`z-50 rounded border border-line bg-surface p-1 text-fg shadow-lg outline-none ${className}`}
        {...props}
      />
    </PopoverPrimitive.Portal>
  );
}
