import { ForensicsConsole } from "../../components/consoles/ForensicsConsole";
export default function Page() {
  return (
    <section className="professional-console tool-console console-enter ">
      <div className="tool-heading">
        <div className="eyebrow">LEDGR.IO / WORKSPACE</div>
        <h1>Investigations</h1>
        <p>Examine a document and trace its provenance.</p>
      </div>
      <ForensicsConsole />
    </section>
  );
}
