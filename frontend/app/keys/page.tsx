import { KeyVaultConsole } from "../../components/consoles/KeyVaultConsole";
export default function Page() {
  return (
    <section className="professional-console tool-console console-enter ">
      <div className="tool-heading">
        <div className="eyebrow">LEDGR.IO / WORKSPACE</div>
        <h1>Key vault</h1>
        <p>Manage your identity and document access keys.</p>
      </div>
      <KeyVaultConsole />
    </section>
  );
}
