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
    <section className="panel mb-3 p-3" aria-labelledby={title ? headingId : undefined}>
      {(title || actions) && (
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          {title && (
            <h2 id={headingId} ref={headingRef} tabIndex={headingRef ? -1 : undefined} className="min-w-0 truncate text-[13px] font-semibold outline-none" title={title}>
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
