import { DocumentDetails } from "../../../components/DocumentDetails";
export default function Page({ params }: { params: { id: string } }) {
  return <DocumentDetails id={params.id} />;
}
