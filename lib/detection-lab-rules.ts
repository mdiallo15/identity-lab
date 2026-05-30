/* ====================================================================== *
 *  Lab rule catalog — one Sigma-equivalent starter rule per lab domain.  *
 *  Server-rendered on /detection-engineering so the corpus never ships   *
 *  to the client bundle.                                                 *
 * ====================================================================== */

import type { Severity } from "./detection";

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
