import RagAnalyzer from "./analyzer";

export const metadata = {
  title: "RAG Security Lab — Marwan Diallo",
  description:
    "Deterministic retrieval-augmented generation attack simulator with poisoned docs, citation forgery, and hardened-agent defenses.",
  openGraph: {
    title: "RAG Security Lab — Marwan Diallo",
    description:
      "Deterministic retrieval-augmented generation attacks and defenses, replayed with observable retrieval math.",
    type: "website",
    url: "https://lab.marwandiallo.com/rag",
  },
  twitter: {
    card: "summary_large_image",
    title: "RAG Security Lab — Marwan Diallo",
    description:
      "Deterministic retrieval-augmented generation attacks and defenses, replayed with observable retrieval math.",
  },
};

export default function RagPage() {
  return <RagAnalyzer />;
}
