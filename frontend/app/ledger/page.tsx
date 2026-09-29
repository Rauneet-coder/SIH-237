import { LedgerConsole } from "../../components/consoles/LedgerConsole";
export default function Page() {
  return (
    <section className="professional-console tool-console console-enter ">
      <div className="tool-heading">
        <div className="eyebrow">LEDGR.IO / WORKSPACE</div>
        <h1>Activity ledger</h1>
        <p>Review document activity and verify its history.</p>
      </div>
      <LedgerConsole />
    </section>
  );
}
