import { NextResponse } from "next/server";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import {
  consumeChallenge,
  getOrCreateUser,
  setChallenge,
  updateCredentialCounter,
} from "@/lib/store";

function getRpInfo(request: Request) {
  const url = new URL(request.url);
  return {
    rpID: url.hostname,
    origin: url.origin,
  };
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return NextResponse.json({ error: "invalid_body" }, { status: 400 });
  }
  const { step, username } = body as { step: string; username: string };
  if (
    typeof username !== "string" ||
    username.length === 0 ||
    username.length > 64
  ) {
    return NextResponse.json({ error: "invalid_username" }, { status: 400 });
  }

  const { rpID, origin } = getRpInfo(request);

  if (step === "options") {
    const user = getOrCreateUser(username);
    if (user.credentials.length === 0) {
      return NextResponse.json(
        { error: "no_credentials", detail: "Register a passkey first." },
        { status: 400 },
      );
    }
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: user.credentials.map((c) => ({
        id: c.credentialID,
        transports: c.transports as AuthenticatorTransport[] | undefined,
      })),
      userVerification: "preferred",
    });
    setChallenge(user.id, options.challenge);
    return NextResponse.json(options);
  }

  if (step === "verify") {
    const user = getOrCreateUser(username);
    const expectedChallenge = consumeChallenge(user.id);
    if (!expectedChallenge) {
      return NextResponse.json({ error: "no_challenge" }, { status: 400 });
    }
    const assertion = (body as { assertion: { id: string } }).assertion;
    const stored = user.credentials.find(
      (c) => c.credentialID === assertion.id,
    );
    if (!stored) {
      return NextResponse.json(
        { error: "unknown_credential" },
        { status: 400 },
      );
    }
    const verification = await verifyAuthenticationResponse({
      response: assertion as never,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: stored.credentialID,
        publicKey: Buffer.from(stored.publicKey, "base64url"),
        counter: stored.counter,
        transports: stored.transports as AuthenticatorTransport[] | undefined,
      },
      requireUserVerification: false,
    });
    if (!verification.verified) {
      return NextResponse.json(
        { error: "verification_failed" },
        { status: 400 },
      );
    }
    updateCredentialCounter(
      user.id,
      stored.credentialID,
      verification.authenticationInfo.newCounter,
    );
    return NextResponse.json({ ok: true });
  }

  return NextResponse.json({ error: "invalid_step" }, { status: 400 });
}
