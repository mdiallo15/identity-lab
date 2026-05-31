import PhishingResistantAnalyzer from "./analyzer";

export const metadata = {
  title: "Phishing-resistant MFA — Identity Lab",
  description:
    "Why FIDO2 / WebAuthn is the only mainstream factor that survives real-time AitM phishing kits, and what makes everything else replayable.",
};

export default function PhishingResistantPage() {
  return (
    <>
      <h1>Phishing-resistant MFA, on the wire</h1>
      <p className="lede">
        Most "MFA" is still replayable. This lab models the four failure modes
        that matter in the field: real-time adversary-in-the-middle proxies,
        helpdesk-led re-enrollment, post-auth cookie theft, and soft fallback
        abuse. Change the factor and the recovery/session controls, then watch
        the attack outcome rerun live.
      </p>

      <PhishingResistantAnalyzer />
    </>
  );
}
