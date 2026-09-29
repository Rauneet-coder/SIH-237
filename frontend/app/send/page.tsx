import { DispatchConsole } from "../../components/consoles/DispatchConsole";
export default function Page() {
  return (
    <section className="tool-console console-enter send-page">
      <div className="tool-heading">
        <div className="eyebrow">LEDGR.IO / WORKSPACE</div>
        <h1>Send a document</h1>
        <p>Choose a document, select its recipients, and send it securely.</p>
      </div>
      <DispatchConsole />
    </section>
  );
}
