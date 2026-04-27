import { ImageResponse } from "next/og";

// Apple touch icon — same shield+L mark, scaled up.

export const size = { width: 180, height: 180 };
export const contentType = "image/png";

export default function AppleIcon() {
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
          borderRadius: "32px",
        }}
      >
        <svg
          viewBox="0 0 64 64"
          width="140"
          height="140"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M32 6 L54 14 L54 32 C54 44 44 54 32 58 C20 54 10 44 10 32 L10 14 Z"
            fill="none"
            stroke="#fafafa"
            strokeWidth="3.5"
            strokeLinejoin="round"
          />
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
