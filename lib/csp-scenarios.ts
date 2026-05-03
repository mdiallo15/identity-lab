// audit-ignore-file
// This catalog deliberately contains insecure CSP fragments and XSS payloads.
// They are demo content rendered inside a sandboxed iframe and never against
// real origins. The audit tool flags 'unsafe-inline', 'unsafe-eval', etc.; that
// is the whole point of the file.
//
// Catalog of CSP bypass / behavior scenarios used by /csp/sandbox.
// Each scenario pairs a CSP header with an HTML payload and an expected
// outcome description, so the user can see "this policy + this payload =
// these violations" in the live iframe console mirror.

export type ScenarioCategory =
  | "baseline"
  | "inline"
  | "eval"
  | "wildcard"
  | "host-allowlist"
  | "base-uri"
  | "object"
  | "strict-dynamic"
  | "nonce"
  | "reporting";

export interface Scenario {
  id: string;
  title: string;
  category: ScenarioCategory;
  csp: string;
  payload: string;
  /** Plain-English summary of what the user should see. */
  expected: string;
  /** Short note on why this fails / passes — the lesson. */
  lesson: string;
  /** Optional standards refs the policy violates. */
  standards?: string[];
}

const HARDENED_CSP = [
  "default-src 'self'",
  "script-src 'nonce-DEMO123' 'strict-dynamic'",
  "style-src 'self' 'nonce-DEMO123'",
  "img-src 'self' data:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const ALLOWLIST_CSP = [
  "default-src 'self'",
  "script-src 'self' https://cdn.jsdelivr.net https://www.googletagmanager.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
].join("; ");

const LOOSE_CSP = [
  "default-src 'self' 'unsafe-inline' 'unsafe-eval' https:",
].join("; ");

export const SCENARIOS: Scenario[] = [
  // -------------------------------------------------------------------- 1
  {
    id: "baseline-strict",
    title: "Hardened nonce policy — inline payload blocked",
    category: "baseline",
    csp: HARDENED_CSP,
    payload: `<h2>Strict policy demo</h2>
<p>The following inline script tries to run without a nonce:</p>
<script>document.body.append('this should not appear');</script>
<p>If the policy works, you'll only see this paragraph and the heading.</p>`,
    expected:
      "Browser blocks the inline <script> because it carries no nonce. CSP violation reported. Page renders, payload string never appended.",
    lesson:
      "A correct nonce policy makes injected inline scripts useless without the per-request token. This is the reference shape.",
    standards: ["NIST SP 800-53 SI-10", "OWASP ASVS V14.4"],
  },

  // -------------------------------------------------------------------- 2
  {
    id: "nonce-runs",
    title: "Nonce'd inline script runs (intended path)",
    category: "nonce",
    csp: HARDENED_CSP,
    payload: `<h2>Nonced script</h2>
<p>This script carries the matching nonce:</p>
<script nonce="DEMO123">
  const p = document.createElement('p');
  p.textContent = '✓ nonced script ran (this is correct)';
  document.body.append(p);
</script>`,
    expected:
      "Script runs because its nonce matches the one in the CSP header. No violation. The confirmation paragraph appears.",
    lesson:
      "Nonces are how legitimate inline code stays inline. Server emits the same nonce in the CSP header and on every script tag it controls.",
  },

  // -------------------------------------------------------------------- 3
  {
    id: "unsafe-inline-event-handler",
    title: "'unsafe-inline' allows DOM event handlers (and so XSS)",
    category: "inline",
    csp: LOOSE_CSP,
    payload: `<h2>Event-handler XSS</h2>
<p>Below is an image that fails to load. With <code>'unsafe-inline'</code>
the <code>onerror</code> handler executes:</p>
<img src="missing.png" onerror="document.body.append('💥 onerror fired — XSS would land here'); this.remove();">
<p>Without <code>'unsafe-inline'</code> in script-src, this attribute is dead.</p>`,
    expected:
      "The onerror handler runs and appends the warning text. No CSP violation, because 'unsafe-inline' explicitly permits attribute event handlers.",
    lesson:
      "'unsafe-inline' on script-src is not just about <script> blocks — it also blesses every onclick/onerror/onload attribute. The vast majority of real XSS payloads use exactly this surface.",
    standards: ["OWASP ASVS V14.4.5"],
  },

  // -------------------------------------------------------------------- 4
  {
    id: "unsafe-eval-runs",
    title: "'unsafe-eval' allows eval() and Function() string construction",
    category: "eval",
    csp: LOOSE_CSP,
    payload: `<h2>eval() under loose CSP</h2>
<script nonce="DEMO123">
  try {
    const fn = new Function("return '✓ Function() ran — eval class allowed'");
    const out = document.createElement('p');
    out.textContent = fn();
    document.body.append(out);
  } catch (e) {
    const out = document.createElement('p');
    out.textContent = '✗ Function() blocked: ' + e.message;
    document.body.append(out);
  }
</script>`,
    expected:
      "Function() / eval() succeeds because the policy includes 'unsafe-eval'. A confirmation line appears.",
    lesson:
      "Modern frameworks (React, Vue, Next.js) compile away eval. If your build still requires 'unsafe-eval' in 2026, audit your toolchain — it's almost always a leftover from Webpack devtool: 'eval-source-map' or AngularJS templates.",
  },

  // -------------------------------------------------------------------- 5
  {
    id: "eval-blocked-strict",
    title: "Strict policy blocks eval()",
    category: "eval",
    csp: HARDENED_CSP,
    payload: `<h2>eval() under strict CSP</h2>
<script nonce="DEMO123">
  try {
    const fn = new Function("return 'this should never appear'");
    const out = document.createElement('p');
    out.textContent = fn();
    document.body.append(out);
  } catch (e) {
    const out = document.createElement('p');
    out.textContent = '✓ blocked by CSP: ' + e.message;
    document.body.append(out);
  }
</script>`,
    expected:
      "Function() throws because 'unsafe-eval' is not in the policy. The catch branch runs and confirms the block.",
    lesson:
      "When 'unsafe-eval' is omitted, the runtime raises an exception at the moment a string-to-code primitive is invoked. Your app sees a clean error you can monitor on.",
  },

  // -------------------------------------------------------------------- 6
  {
    id: "wildcard-https",
    title: "Wildcard https: trusts the entire web",
    category: "wildcard",
    csp: "default-src 'self'; script-src https:",
    payload: `<h2>Wildcard https: scheme</h2>
<p>script-src is just <code>https:</code>. Below is a script tag that
points at any HTTPS origin. Under the policy, the browser will fetch
and run it. (Demo only — we point at a self-host so nothing actually
loads in the sandbox, but no CSP violation will fire.)</p>
<script src="https://example.com/whatever.js"></script>
<script nonce="DEMO123">
  document.body.append(Object.assign(document.createElement('p'), {
    textContent: 'No CSP violation was raised — the URL was trusted by scheme alone.'
  }));
</script>`,
    expected:
      "No CSP violation event for the cross-origin script tag (the URL fetch may fail, but CSP itself permitted it). The diagnostic paragraph confirms.",
    lesson:
      "Bare scheme sources (https:, http:) effectively disable the allowlist. Treat them as a code smell — they almost never reflect a real trust relationship.",
  },

  // -------------------------------------------------------------------- 7
  {
    id: "jsonp-allowlist-bypass",
    title: "JSONP bypass — CDN allowlist is in the host",
    category: "host-allowlist",
    csp: ALLOWLIST_CSP,
    payload: `<h2>JSONP on an allowlisted host</h2>
<p>script-src includes <code>https://cdn.jsdelivr.net</code>. An attacker
injects a script tag pointing at a JSONP endpoint on the same host with
a callback name of their choice:</p>
<pre>&lt;script src="https://cdn.jsdelivr.net/...?callback=alert(1)"&gt;&lt;/script&gt;</pre>
<p>The browser would happily fetch it (CSP is satisfied — the host is on
the allowlist) and execute the returned payload. We don't actually load
the script in this sandbox; the box below shows what the browser sees.</p>
<p style="color: #f87171;"><strong>CSP would not fire any violation.</strong>
The policy trusted the host; the host trusted the caller.</p>`,
    expected:
      "No violation. The lesson is what the browser would have done with a real JSONP endpoint on a trusted CDN.",
    lesson:
      "Host allowlists are only as strong as the most permissive endpoint on each allowlisted host. Modern advice: avoid host allowlists for script-src. Use 'strict-dynamic' + nonce instead — the host list becomes irrelevant.",
    standards: ["W3C CSP3 'strict-dynamic'"],
  },

  // -------------------------------------------------------------------- 8
  {
    id: "base-uri-dangling-markup",
    title: "Missing base-uri → dangling markup attack",
    category: "base-uri",
    csp: "default-src 'self'; script-src 'self' 'nonce-DEMO123'",
    payload: `<h2>base-uri not set</h2>
<p>An XSS that can inject a single tag (no script execution required)
inserts: <code>&lt;base href="https://attacker.example"&gt;</code></p>
<base href="https://attacker.example/">
<p>Now every relative URL on this page resolves against the attacker
domain. Below is a relative-src image and link — open the iframe DevTools
network tab and you'll see them resolve to the attacker host:</p>
<img src="/logo.png" alt="relative img">
<a href="/login">relative login link</a>
<p style="color: #f87171;"><strong>No CSP violation</strong> — the
&lt;base&gt; tag itself isn't restricted by script-src, and base-uri
wasn't set.</p>`,
    expected:
      "No script-src violation. Network panel will show /logo.png resolving to attacker.example/logo.png. Adding base-uri 'self' would have raised a CSP violation on the <base> tag.",
    lesson:
      "base-uri 'self' is one line and prevents an entire class of attack. Always include it. The dangling-markup variant is especially nasty because it doesn't need script execution — just an HTML injection point.",
    standards: ["W3C CSP3 §6.4.6"],
  },

  // -------------------------------------------------------------------- 9
  {
    id: "object-src-missing",
    title: "object-src not locked — <object> loads",
    category: "object",
    csp: "default-src 'self'; script-src 'self' 'nonce-DEMO123'",
    payload: `<h2>Missing object-src</h2>
<p>Without an explicit <code>object-src 'none'</code>, plugins can be
embedded. Below is an <code>&lt;object&gt;</code> tag pointing at a
data URI:</p>
<object data="data:text/html,<script>alert('object body ran')</script>"
        type="text/html" width="240" height="40"></object>
<p>Modern browsers sandbox the inner document, but this is still a
historical XSS surface (Flash, PDF plugins). object-src 'none' is the
clean fix.</p>`,
    expected:
      "Browser may render an empty placeholder. With object-src 'none' the entire tag is dead.",
    lesson:
      "Almost no app in 2026 needs <object> or <embed>. Set object-src 'none' explicitly — don't rely on the absence of plugins.",
  },

  // -------------------------------------------------------------------- 10
  {
    id: "strict-dynamic-no-nonce",
    title: "'strict-dynamic' without nonce — silent failure",
    category: "strict-dynamic",
    csp: "default-src 'self'; script-src 'strict-dynamic' https:",
    payload: `<h2>strict-dynamic without nonce or hash</h2>
<p>script-src has <code>'strict-dynamic'</code> but no nonce and no hash.
Per spec, <code>'strict-dynamic'</code> disables host allowlists but
also requires a nonce or hash to bootstrap. With neither, no script
runs at all:</p>
<script>document.body.append('this never runs');</script>
<script src="https://example.com/x.js"></script>
<p>You'll see CSP violations for both, even though https: is in the
policy — <code>'strict-dynamic'</code> overrode it.</p>`,
    expected:
      "Both script tags blocked. Two CSP violations reported. The page is silent because nothing has a valid nonce/hash to start the trust chain.",
    lesson:
      "A copy-pasted 'strict-dynamic' without the accompanying nonce is a self-DoS. The fix is one of: add 'nonce-X' and stamp it on every legitimate script, or remove 'strict-dynamic' until you can.",
  },
];

/** Helper used by the sandbox UI to look up a scenario by id. */
export function scenarioById(id: string): Scenario | undefined {
  return SCENARIOS.find((s) => s.id === id);
}

export const HARDENED_STARTER = HARDENED_CSP;
