import { ImageResponse } from "next/og";

// Dynamically generated favicon. App Router picks this up automatically
// at /icon and emits the right <link rel="icon"> in <head>. Next.js
// caches the result, so this only renders at build time per size.
//
// Mark: a shield outline with an angled "L" (labs). Solid ink on the
// site's signature warm-paper background so it reads at 16px.

export const size = { width: 64, height: 64 };
export const contentType = "image/png";

export default function Icon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#0a0a0a",
        }}
      >
        <svg
          viewBox="0 0 64 64"
          width="64"
          height="64"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Shield outline */}
          <path
            d="M32 6 L54 14 L54 32 C54 44 44 54 32 58 C20 54 10 44 10 32 L10 14 Z"
            fill="none"
            stroke="#fafafa"
            strokeWidth="3.5"
            strokeLinejoin="round"
          />
          {/* L mark */}
          <path
            d="M24 22 L24 42 L42 42"
            fill="none"
            stroke="#fafafa"
            strokeWidth="5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>
    ),
    { ...size },
  );
}
