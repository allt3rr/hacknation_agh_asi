import type { Notice } from "../hooks";

export function NoticeBar({ notice }: { notice: Notice | null }) {
  if (!notice) {
    return null;
  }
  return <p className={`my-3.5 ${notice.kind === "error" ? "text-red" : "text-muted"}`}>{notice.text}</p>;
}
