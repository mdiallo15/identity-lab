import CspShapesAnalyzer from "./analyzer";

export const metadata = {
  title: "Four CSP shapes — Labs",
};

export default function Shapes() {
  return (
    <>
      <h1>The four CSP shapes</h1>
      <p className="lede">
        Describe the app you are securing and the lab recommends the CSP shape
        that matches those constraints. The sample policy and findings rerun
        live as the constraints change.
      </p>

      <CspShapesAnalyzer />
    </>
  );
}
