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
