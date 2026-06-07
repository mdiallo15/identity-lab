import IamPrivescAnalyzer from "./analyzer";

export const metadata = {
  title: "IAM PrivEsc Lab — Marwan Diallo",
  description:
    "Multi-cloud IAM privilege-escalation path enumerator across AWS, Azure, and GCP with editable principals and live path generation.",
  openGraph: {
    title: "IAM PrivEsc Lab — Marwan Diallo",
    description:
      "Editable multi-cloud privilege-escalation graph with published AWS, Azure, and GCP techniques.",
    type: "website",
    url: "https://lab.marwandiallo.com/iam-privesc",
  },
  twitter: {
    card: "summary_large_image",
    title: "IAM PrivEsc Lab — Marwan Diallo",
    description:
      "Editable multi-cloud privilege-escalation graph with published AWS, Azure, and GCP techniques.",
  },
};

export default function IamPrivescPage() {
  return <IamPrivescAnalyzer />;
}
