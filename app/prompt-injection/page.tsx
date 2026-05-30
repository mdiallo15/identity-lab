import Link from "next/link";
import { LearnCallout } from "@/app/_components/learn-callout";
import { ThreatModelCard } from "@/app/_components/threat-model";
import type { ThreatEntry } from "@/lib/labs";

const THREATS: readonly ThreatEntry[] = [
  {
    stride: "S",
    threat: "Untrusted document spoofs system-role instructions.",
    demo: { label: "simulator", href: "/prompt-injection/simulator" },
  },
  {
    stride: "T",
    threat: "Tool description tampering pivots `send_email` arguments.",
    demo: { label: "patterns", href: "/prompt-injection/patterns" },
  },
  {
    stride: "I",
    threat: "Markdown-image canary exfils chat history off-domain.",
    demo: { label: "simulator", href: "/prompt-injection/simulator" },
  },
  {
    stride: "E",
    threat: "Confused-deputy: agent runs privileged tool on user's behalf.",
    demo: { label: "defenses", href: "/prompt-injection/defenses" },
  },
];

export const metadata = {
  title: "Prompt Injection Lab — Labs",
  description:
    "Indirect prompt injection, tool-call hijacking, exfiltration via markdown images. Side-by-side simulator of a naive vs hardened agent on the same untrusted document.",
};

export default function PromptInjectionOverview() {
  return (
    <>
      <h1>Prompt Injection Lab</h1>
      <LearnCallout href="/prompt-injection" />
      <ThreatModelCard entries={THREATS} />
      <p className="lede">
        The XSS of the LLM era. An attacker plants instructions inside data an
        agent ingests — a webpage, a ticket, a resume, a README — and the agent
        treats those instructions as if they came from its operator. The
        defenses look a lot like the ones we already use for HTML.
      </p>

      <div className="hero-stat">
        <strong>Zero LLM calls.</strong> This lab is a deterministic simulator.
        It demonstrates the attack patterns and defense primitives without you
        needing an API key, without me paying for tokens, and with results you
        can reproduce in a code review.
      </div>

      <div className="cards">
        <Link href="/prompt-injection/simulator" className="card">
          <h2>Simulator →</h2>
          <p>
            Pick an attacker-crafted document. Watch a naive agent follow the
            injected instructions and a hardened agent refuse them. Includes 6
            real-world patterns: direct override, exfiltration via markdown
            image, fake tool-call boundary, white-on-white text, on-behalf-of
            confusion.
          </p>
        </Link>

        <Link href="/prompt-injection/patterns" className="card">
          <h2>Attack patterns →</h2>
          <p>
            10 detector rules (PI01–PI10) covering the patterns I see most
            often: <code>ignore previous instructions</code>, counterfeit
            <code>[SYSTEM]</code> markers, hidden HTML comments, CSS-hidden
            text, exfiltration query-strings, fake tool-call JSON, shell-command
            smuggling, role hijack, base64 obfuscation.
          </p>
        </Link>

        <Link href="/prompt-injection/defenses" className="card">
          <h2>Defenses →</h2>
          <p>
            Spotlighting, structured prompts, instruction-vs-data separation,
            tool-call provenance, image-render policies, and the agent-identity
            controls that turn an injection from "RCE on production" into "model
            said something weird."
          </p>
        </Link>
      </div>

      <h2>Read in order</h2>
      <ol>
        <li>
          <Link href="/prompt-injection/simulator">Simulator</Link> — see the
          attacks land (or not) on identical agents that differ only in their
          prompt structure.
        </li>
        <li>
          <Link href="/prompt-injection/patterns">Patterns</Link> — the full
          catalog of what to look for in untrusted content.
        </li>
        <li>
          <Link href="/prompt-injection/defenses">Defenses</Link> — what to
          actually ship.
        </li>
      </ol>

      <h2>Why this lab is backendless</h2>
      <p>
        The point isn't to run an LLM. It's to teach the failure mode. A
        deterministic simulator beats a flaky live demo because the lesson is
        reproducible: every visitor sees the same attack land the same way. If
        you want to stress-test a real agent against these patterns, the corpus
        in{" "}
        <a
          href="https://github.com/mdiallo15/identity-lab/blob/main/lib/prompt-injection.ts"
          target="_blank"
          rel="noopener noreferrer"
        >
          <code>lib/prompt-injection.ts</code>
        </a>{" "}
        is a starting point — paste each sample into your model of choice and
        compare its behavior to the hardened simulator.
      </p>

      <h2>Pairs with</h2>
      <p>
        The on-behalf-of confusion sample (#6 in the simulator) is the same gap
        covered in the{" "}
        <Link href="/identity/agent-identity">Agent identity</Link> page. An
        injected instruction is only catastrophic if the agent has the privilege
        to execute it. Workload identity, scoped delegation, and per-action
        confirmation are how you contain the blast radius.
      </p>
    </>
  );
}
