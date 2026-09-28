import { LedgerConsole } from "../../components/consoles/LedgerConsole";
export default function Page() {
  return (
    <section className="tool-console console-enter ">
      <div className="tool-heading">
        <div className="eyebrow">PRAMAAN / WORKSPACE</div>
        <h1>Activity ledger</h1>
        <p>Review document activity and verify its history.</p>
      </div>
      <LedgerConsole />
    </section>
  );
}
