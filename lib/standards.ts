// audit-ignore-file
// Centralized "light" standards mapping used by the lab pattern + analyzer
// pages. Each rule ID is annotated with the smallest set of authoritative
// references that would let a reader trace the finding back to a published
// control, framework, or specification. Kept light on purpose — a full
// crosswalk lives in the consulting writeups, not the lab UI.

export const STANDARDS_BY_ID: Record<string, string[]> = {
  // ---- CSP analyzer (lib/csp.ts) ----
  CSP01: ["OWASP Top 10 A05", "MDN CSP", "W3C CSP3"],
  CSP02: ["OWASP CSP CS", "OWASP Top 10 A03", "W3C CSP3 §6.6"],
  CSP03: ["OWASP Top 10 A03", "W3C CSP3 §6.6"],
  CSP04: ["OWASP CSP CS", "W3C CSP3 §6.6"],
  CSP05: ["OWASP CSP CS", "W3C CSP3 §6.6"],
  CSP06: ["OWASP CSP CS", "W3C CSP3"],
  CSP07: ["OWASP CSP CS", "W3C CSP3 §6.4"],
  CSP08: ["OWASP Top 10 A05", "W3C CSP3 §6.4 (frame-ancestors)"],
  CSP09: ["OWASP CSP CS"],
  CSP10: ["OWASP Top 10 A05"],
  CSP11: ["W3C CSP3 §6.5 (reporting)", "NIST CSF 2.0 DE.CM"],
  CSP12: ["W3C CSP3 §6.7", "Mozilla Web Security Guidelines"],

  // ---- SSRF analyzer (lib/ssrf.ts) ----
  SSRF00: ["—"],
  SSRF01: [
    "OWASP Top 10 A10 (SSRF)",
    "CWE-918",
    "AWS IMDSv2 guidance",
    "Capital One 2019 (post-mortem)",
  ],
  SSRF02: ["OWASP Top 10 A10", "CWE-918", "RFC 3927 (link-local)"],
  SSRF03: ["OWASP Top 10 A10", "CWE-918"],
  SSRF04: ["OWASP Top 10 A10", "CWE-918", "RFC 1918"],
  SSRF05: ["OWASP Top 10 A10", "CWE-939"],
  SSRF06: ["OWASP Top 10 A10", "CWE-918", "PortSwigger SSRF research"],
  SSRF07: ["OWASP Top 10 A10"],
  SSRF08: ["OWASP Top 10 A10", "CWE-918", "MSRC IMDS guidance"],

  // ---- Prompt injection (lib/prompt-injection.ts) ----
  PI01: ["OWASP LLM Top 10 LLM01", "NIST AI 600-1 §2.4"],
  PI02: ["OWASP LLM Top 10 LLM01", "NIST AI 600-1 §2.4"],
  PI03: ["OWASP LLM Top 10 LLM01 (indirect)", "NIST AI 600-1 §2.4"],
  PI04: ["OWASP LLM Top 10 LLM01 (indirect)", "NIST AI 600-1 §2.4"],
  PI05: ["OWASP LLM Top 10 LLM02 (data leakage)", "NIST AI 600-1 §2.5"],
  PI06: ["OWASP LLM Top 10 LLM02", "NIST AI 600-1 §2.5"],
  PI07: ["OWASP LLM Top 10 LLM07 (insecure plugin)", "OAuth RFC 8693"],

  // ---- AuthZ / BOLA (lib/authz.ts) ----
  BOLA01: [
    "OWASP API Top 10 API1",
    "CWE-639",
    "NIST SP 800-53 AC-3",
    "PCI-DSS 4.0 §7.2.5",
  ],
  BOLA02: ["OWASP API Top 10 API1", "CWE-204"],
  BOLA03: ["OWASP API Top 10 API1", "CWE-340"],
  BOLA04: ["OWASP API Top 10 API1", "CWE-285", "NIST SP 800-53 AC-3"],
  BOLA05: ["OWASP API Top 10 API3", "CWE-915"],
  BOLA06: ["OWASP API Top 10 API5", "CWE-285"],
  BOLA07: ["OWASP API Top 10 API1", "CWE-639"],
  BOLA08: ["OWASP Top 10 A04", "CWE-209"],

  // ---- Agent identity drift (lib/agent-identity.ts) ----
  AGT01: [
    "NIST SP 800-63-4 (NPE)",
    "CIS Controls v8 5.5",
    "OWASP NHI Top 10 NHI04",
  ],
  AGT02: [
    "NIST AI 600-1 §2.5",
    "CSA AI Controls Matrix",
    "NIST CSF 2.0 PR.AA",
  ],
  AGT03: [
    "CIS Controls v8 6.8",
    "NIST SP 800-53 AC-2 / AC-6",
  ],
  AGT04: ["OWASP API Top 10 API5", "CIS Controls v8 6.8"],
  AGT05: ["CIS Controls v8 5.3", "NIST SP 800-53 AC-2(3)"],
  AGT06: [
    "NIST SP 800-63-4 (NPE)",
    "NIST CSF 2.0 GV.RR",
    "CIS Controls v8 5",
  ],
  AGT07: [
    "OAuth RFC 8693 (act claim)",
    "NIST SP 800-92 audit guidance",
    "NIST CSF 2.0 DE.AE",
  ],
  AGT08: [
    "NIST SP 800-53 AC-2(9)",
    "CIS Controls v8 5.4",
    "SPIFFE workload identity",
  ],
};

export function standardsFor(id: string): string[] | undefined {
  const refs = STANDARDS_BY_ID[id];
  if (!refs || refs.length === 0 || (refs.length === 1 && refs[0] === "—")) {
    return undefined;
  }
  return refs;
}
