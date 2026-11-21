import { useId, type ReactNode, type Ref } from "react";

interface CardProps {
  title?: string;
  actions?: ReactNode;
  children: ReactNode;
  /** Pozwala przenieść fokus na nagłówek (np. po otwarciu szczegółów). */
  headingRef?: Ref<HTMLHeadingElement>;
}

export function Card({ title, actions, children, headingRef }: CardProps) {
  const headingId = useId();
  return (
    <section className="glass animate-rise mb-5 p-5" aria-labelledby={title ? headingId : undefined}>
      {(title || actions) && (
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          {title && (
            <h2 id={headingId} ref={headingRef} tabIndex={headingRef ? -1 : undefined} className="flex items-center gap-2 text-base font-semibold outline-none">
              <span aria-hidden="true" className="brand-gradient h-4 w-1 rounded-full" />
              {title}
            </h2>
          )}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}
