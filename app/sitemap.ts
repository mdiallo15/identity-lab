import type { MetadataRoute } from "next";

const BASE_URL = "https://lab.marwandiallo.com";

const ROUTES = [
  "/",
  "/identity",
  "/identity/passkey",
  "/identity/jwt",
  "/identity/forge",
  "/identity/phishing-resistant",
  "/identity/agent-identity",
  "/agent-identity",
  "/agent-identity/attestation",
  "/agent-identity/inventory",
  "/agent-identity/token-exchange",
  "/csp",
  "/csp/analyzer",
  "/csp/sandbox",
  "/csp/bypasses",
  "/csp/shapes",
  "/authz",
  "/authz/simulator",
  "/authz/patterns",
  "/ssrf",
  "/ssrf/analyzer",
  "/ssrf/targets",
  "/ssrf/hardening",
  "/prompt-injection",
  "/prompt-injection/simulator",
  "/prompt-injection/patterns",
  "/prompt-injection/defenses",
  "/iam-privesc",
  "/detection-engineering",
  "/supply-chain",
  "/rag",
] as const;

export default function sitemap(): MetadataRoute.Sitemap {
  const lastModified = new Date();
  return ROUTES.map((route) => ({
    url: `${BASE_URL}${route}`,
    lastModified,
    changeFrequency: route === "/" ? "weekly" : "monthly",
    priority: route === "/" ? 1 : route.includes("/analyzer") || route.includes("/simulator") ? 0.9 : 0.8,
  }));
}
