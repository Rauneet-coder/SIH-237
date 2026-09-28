import Link from "next/link";
import { InboxConsole } from "../../../../components/consoles/InboxConsole";
export default function Page({ params }: { params: { id: string } }) {
  return (
    <section className="tool-console">
      <Link
        className="detail-back"
        href={`/documents/${encodeURIComponent(params.id)}`}
      >
        ← Back to document details
      </Link>
      <div className="tool-heading">
        <h1>Secure viewer</h1>
        <p>Open a controlled session for this document.</p>
      </div>
      <InboxConsole key={params.id} documentId={params.id} />
    </section>
  );
}
