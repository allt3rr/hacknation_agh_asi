import type { Notice } from "../hooks";

export function NoticeBar({ notice }: { notice: Notice | null }) {
  if (!notice) {
    return null;
  }
  return <p className={notice.kind === "error" ? "notice error" : "notice"}>{notice.text}</p>;
}
