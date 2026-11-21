import type { ReactNode } from "react";

interface CardProps {
  title?: string;
  actions?: ReactNode;
  children: ReactNode;
}

export function Card({ title, actions, children }: CardProps) {
  return (
    <section className="mb-4 rounded-[10px] border border-line bg-surface p-4">
      {(title || actions) && (
        <div className="mb-2 flex items-center justify-between gap-2">
          {title && <h3 className="text-[1.17em] font-bold">{title}</h3>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}
