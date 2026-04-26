import { NextResponse } from "next/server";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import {
  addCredential,
  consumeChallenge,
  getOrCreateUser,
  setChallenge,
} from "@/lib/store";

function getRpInfo(request: Request) {
  const url = new URL(request.url);
  return {
    rpName: "Identity Lab",
    rpID: url.hostname, // localhost works in dev
    origin: url.origin,
  };
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return NextResponse.json({ error: "invalid_body" }, { status: 400 });
  }
  const { step, username } = body as { step: string; username: string };
  if (typeof username !== "string" || username.length === 0 || username.length > 64) {
    return NextResponse.json({ error: "invalid_username" }, { status: 400 });
  }

  const { rpName, rpID, origin } = getRpInfo(request);

  if (step === "options") {
    const user = getOrCreateUser(username);
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: new TextEncoder().encode(user.id),
      userName: user.username,
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      excludeCredentials: user.credentials.map((c) => ({
        id: c.credentialID,
        transports: c.transports as AuthenticatorTransport[] | undefined,
      })),
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
    const verification = await verifyRegistrationResponse({
      response: (body as { attestation: unknown }).attestation as never,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return NextResponse.json({ error: "verification_failed" }, { status: 400 });
    }

    const reg = verification.registrationInfo;
    addCredential(user.id, {
      credentialID: reg.credential.id,
      publicKey: Buffer.from(reg.credential.publicKey).toString("base64url"),
      counter: reg.credential.counter,
      transports: reg.credential.transports,
    });
    return NextResponse.json({ ok: true });
  }

  return NextResponse.json({ error: "invalid_step" }, { status: 400 });
}
