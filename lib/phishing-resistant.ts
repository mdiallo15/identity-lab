export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
}

export interface Reference {
  label: string;
  url: string;
}

export interface Factor {
  id: "sms" | "totp" | "push" | "passkey";
  label: string;
  blurb: string;
}

export interface AttackScenario {
  id: "aitm" | "helpdesk" | "cookie-theft" | "fallback";
  title: string;
  blurb: string;
  references: Reference[];
}

export interface LabInput {
  factorId: Factor["id"];
  attackId: AttackScenario["id"];
  fallbackEnabled: boolean;
  helpdeskResetWeak: boolean;
  tokenBindingEnabled: boolean;
  numberMatchingEnabled: boolean;
}

export interface TraceStep {
  label: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

export const FACTORS: readonly Factor[] = [
  {
    id: "sms",
    label: "SMS / voice OTP",
    blurb:
      "Cheap to deploy, easy to replay, and easy to social-engineer around.",
  },
  {
    id: "totp",
    label: "TOTP app",
    blurb:
      "Stronger than SMS, but a reverse-proxy can still replay the 30-second code in real time.",
  },
  {
    id: "push",
    label: "Push MFA",
    blurb:
      "Number matching helps, but a user can still approve a proxied or fatigued prompt.",
  },
  {
    id: "passkey",
    label: "FIDO2 / WebAuthn passkey",
    blurb:
      "Origin-bound public-key auth. The phishing site gets a signature for the wrong origin.",
  },
] as const;

export const ATTACKS: readonly AttackScenario[] = [
  {
    id: "aitm",
    title: "Real-time adversary-in-the-middle proxy",
    blurb:
      "Evilginx / EvilProxy style kits relay the exact login ceremony to the real site and steal whatever the victim can replay.",
    references: [
      {
        label: "Microsoft, 'EvilProxy phishing as a service'",
        url: "https://www.microsoft.com/en-us/security/blog/2023/07/12/evilproxy-service-lets-attackers-bypass-mfa-phish-session-cookies/",
      },
      {
        label: "NIST SP 800-63B §5.1 phishing resistance",
        url: "https://pages.nist.gov/800-63-4/sp800-63b.html",
      },
    ],
  },
  {
    id: "helpdesk",
    title: "Helpdesk-led re-enrollment",
    blurb:
      "Scattered Spider style social engineering shifts the problem from crypto to recovery workflow. MGM and Caesars both turned on this path.",
    references: [
      {
        label: "CISA / FBI / MS-ISAC on Scattered Spider",
        url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a",
      },
      {
        label: "CISA on social-engineering help-desk bypass",
        url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a",
      },
    ],
  },
  {
    id: "cookie-theft",
    title: "Post-auth session cookie theft",
    blurb:
      "Infostealers and endpoint malware do not break MFA; they steal the already-issued session. Token binding / DPoP is the compensating control.",
    references: [
      {
        label: "RFC 9449 DPoP",
        url: "https://datatracker.ietf.org/doc/html/rfc9449",
      },
      {
        label: "Microsoft on token theft and session replay",
        url: "https://www.microsoft.com/en-us/security/blog/2024/01/11/new-midnight-blizzard-campaign-targets-hospitality-sector-with-identity-attacks/",
      },
    ],
  },
  {
    id: "fallback",
    title: "Soft fallback path abuse",
    blurb:
      "An org advertises passkeys but still exposes OTP or push when the attacker says the passkey failed. The attacker chooses the weaker rail.",
    references: [
      {
        label: "NIST SP 800-63B AAL guidance",
        url: "https://pages.nist.gov/800-63-4/sp800-63b.html#aal",
      },
      {
        label: "OWASP MFA Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
      },
    ],
  },
] as const;

function push(
  findings: Finding[],
  severity: Severity,
  id: string,
  title: string,
  detail: string,
  fix: string,
) {
  findings.push({ id, severity, title, detail, fix });
}

export function analyzeMfa(input: LabInput): {
  findings: Finding[];
  trace: TraceStep[];
  outcome: "blocked" | "degraded" | "compromised";
} {
  const findings: Finding[] = [];
  const trace: TraceStep[] = [];

  trace.push({
    label: "Primary factor",
    status: "ok",
    detail: FACTORS.find((f) => f.id === input.factorId)?.label ?? input.factorId,
  });

  if (input.attackId === "aitm") {
    trace.push({
      label: "Attacker relays sign-in in real time",
      status: "warn",
      detail:
        "The reverse proxy forwards credentials, second factor, and any session cookie the real site issues.",
    });
    if (input.factorId === "passkey") {
      trace.push({
        label: "Authenticator signs origin",
        status: "ok",
        detail:
          "The phishing origin is wrong, so the WebAuthn assertion does not validate at the real relying party.",
      });
      if (input.fallbackEnabled) {
        push(
          findings,
          "high",
          "MFA01",
          "Passkey primary but soft fallback present",
          "WebAuthn blocks the proxy, but the attacker can deliberately fail the passkey step and force the user onto a replayable OTP/push rail.",
          "Gate privileged flows to phishing-resistant-only auth. Do not expose OTP or push as a rescue path for the same transaction.",
        );
        return { findings, trace, outcome: "degraded" };
      }
      push(
        findings,
        "info",
        "MFA02",
        "Origin binding stops real-time relay",
        "This is the property NIST means by phishing resistance: the authenticator signs the origin the browser is actually on.",
        "Keep passkey-only for high-value roles and block weaker fallback factors.",
      );
      return { findings, trace, outcome: "blocked" };
    }

    if (input.factorId === "push" && input.numberMatchingEnabled) {
      push(
        findings,
        "medium",
        "MFA03",
        "Push + number matching still depends on user judgement",
        "Number matching raises attacker cost, but a real-time relay can still social-engineer the prompt or wait for fatigue.",
        "Use passkeys for admin paths. Treat push as improved MFA, not phishing-resistant MFA.",
      );
      return { findings, trace, outcome: "degraded" };
    }

    push(
      findings,
      "critical",
      "MFA04",
      "Replayable factor under real-time proxy",
      "SMS, TOTP, and ordinary push flows can all be proxied. The attacker does not need to break the factor, only to relay it before expiry.",
      "Move the transaction to WebAuthn / passkeys and eliminate weaker fallback rails for the same account tier.",
    );
    return { findings, trace, outcome: "compromised" };
  }

  if (input.attackId === "helpdesk") {
    trace.push({
      label: "Recovery workflow invoked",
      status: input.helpdeskResetWeak ? "fail" : "ok",
      detail: input.helpdeskResetWeak
        ? "The helpdesk can reset or re-enroll the factor on a phone call alone."
        : "Recovery requires strong identity proofing or an already-trusted device.",
    });
    if (input.helpdeskResetWeak) {
      push(
        findings,
        "critical",
        "MFA05",
        "Recovery path defeats the factor",
        "The cryptography on the factor no longer matters once the attacker can socially engineer re-enrollment through support.",
        "Require identity proofing, trusted-device recovery, or admin break-glass with strong out-of-band verification.",
      );
      return { findings, trace, outcome: "compromised" };
    }

    push(
      findings,
      "info",
      "MFA06",
      "Recovery workflow holds the line",
      "The factor is only as strong as the re-enrollment path. Here, recovery preserves the original assurance level.",
      "Keep recovery evidence at the same or higher assurance than the production factor.",
    );
    return { findings, trace, outcome: "blocked" };
  }

  if (input.attackId === "cookie-theft") {
    trace.push({
      label: "Attacker steals post-auth session",
      status: input.tokenBindingEnabled ? "warn" : "fail",
      detail: input.tokenBindingEnabled
        ? "The attacker has the cookie, but the API expects proof-of-possession from the original client key."
        : "The stolen bearer token is reusable from any device until expiry.",
    });
    if (!input.tokenBindingEnabled) {
      push(
        findings,
        "high",
        "MFA07",
        "Session is a bearer artifact",
        "Phishing-resistant MFA only protects the ceremony. Without sender-constrained sessions, infostealers replay the resulting cookie unchanged.",
        "Adopt DPoP or another sender-constrained session model on the highest-risk APIs and shorten privileged-session TTLs.",
      );
      return { findings, trace, outcome: "compromised" };
    }

    push(
      findings,
      "medium",
      "MFA08",
      "Factor survives but session protection must be end-to-end",
      "Sender-constrained sessions blunt cookie replay, but only where every relying party enforces proof-of-possession correctly.",
      "Keep DPoP or equivalent bound to the full privileged session surface, not just the login endpoint.",
    );
    return { findings, trace, outcome: "degraded" };
  }

  trace.push({
    label: "Fallback policy evaluated",
    status: input.fallbackEnabled ? "fail" : "ok",
    detail: input.fallbackEnabled
      ? "The operator can fall back to a replayable factor when the primary factor fails."
      : "No weaker factor is exposed for the same assurance tier.",
  });
  if (input.fallbackEnabled) {
    push(
      findings,
      "high",
      "MFA09",
      "Soft fallback creates a downgrade path",
      "The attacker does not need to beat the strong factor if they can reliably steer the user into SMS, TOTP, or push for the same action.",
      "Separate account recovery from transaction authorization. Keep high-value admin actions on phishing-resistant-only auth.",
    );
    return { findings, trace, outcome: "compromised" };
  }

  push(
    findings,
    "info",
    "MFA10",
    "No weak fallback exposed",
    "The session can only proceed on the primary rail, so the attacker cannot intentionally downgrade the victim to something replayable.",
    "Keep the rescue workflow out of the live auth path.",
  );
  return { findings, trace, outcome: "blocked" };
}