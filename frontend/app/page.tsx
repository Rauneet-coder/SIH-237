"use client";
import { useRouter } from "next/navigation";
import { OverviewConsole } from "../components/consoles/OverviewConsole";
import { consoleTabs } from "../components/ConsoleNav";
export default function Home() {
  const router = useRouter();
  return (
    <OverviewConsole
      onNavigate={(tab) =>
        router.push(consoleTabs.find((t) => t.id === tab)?.href || "/")
      }
    />
  );
}
