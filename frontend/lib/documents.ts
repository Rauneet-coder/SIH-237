import { DocumentMeta, User } from "./api";
export function documentId(doc: DocumentMeta) {
  return doc._id || doc.id || "";
}
export function isSent(doc: DocumentMeta, user: User | null) {
  const sender = doc.senderId;
  return (
    !!user &&
    !!sender &&
    ((sender._id || sender.id) === (user._id || user.id) ||
      sender.username === user.username)
  );
}
export function isReceived(doc: DocumentMeta, user: User | null) {
  if (!user) return false;
  const id = user._id || user.id;
  return (
    !!doc.recipientKeys?.some((k) =>
      typeof k.recipientId === "string"
        ? k.recipientId === id
        : (k.recipientId?._id || k.recipientId?.id) === id ||
          k.recipientId?.username === user.username,
    ) || !!doc.keyEnvelopes?.some((k) => k.recipientId === id)
  );
}
export function recipientCount(doc: DocumentMeta) {
  return (
    doc.recipientCount ??
    (doc.keyEnvelopes?.length || doc.recipientKeys?.length || 0)
  );
}
export function fileSize(bytes: number) {
  return Number.isFinite(bytes)
    ? bytes >= 1048576
      ? `${(bytes / 1048576).toFixed(1)} MB`
      : `${(bytes / 1024).toFixed(1)} KB`
    : "Unavailable";
}
export function dateLabel(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unavailable"
    : date.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      });
}
