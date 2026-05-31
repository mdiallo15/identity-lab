import CspBypassAnalyzer from "./analyzer";

export const metadata = {
  title: "CSP bypasses — Labs",
};

export default function Bypasses() {
  return (
    <>
      <h1>How CSPs get bypassed</h1>
      <p className="lede">
        A policy is only as strong as its weakest source. This lab replays the
        five bypass patterns that show up most often in real engagements, with
        editable policy text and a concrete payload under test.
      </p>

      <CspBypassAnalyzer />
    </>
  );
}
