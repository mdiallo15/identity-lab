// In-memory user / passkey store for the demo.
// In production you'd persist credentials in a database keyed by userId
// with the public key, sign count, transports, and aaguid.

export interface StoredCredential {
  credentialID: string; // base64url
  publicKey: string; // base64url
  counter: number;
  transports?: string[];
}

export interface DemoUser {
  id: string;
  username: string;
  credentials: StoredCredential[];
  currentChallenge?: string;
}

const users = new Map<string, DemoUser>();

export function getOrCreateUser(username: string): DemoUser {
  const existing = [...users.values()].find((u) => u.username === username);
  if (existing) return existing;
  const u: DemoUser = {
    id: crypto.randomUUID(),
    username,
    credentials: [],
  };
  users.set(u.id, u);
  return u;
}

export function getUserById(id: string): DemoUser | undefined {
  return users.get(id);
}

export function setChallenge(userId: string, challenge: string): void {
  const u = users.get(userId);
  if (u) u.currentChallenge = challenge;
}

export function consumeChallenge(userId: string): string | undefined {
  const u = users.get(userId);
  if (!u) return undefined;
  const c = u.currentChallenge;
  u.currentChallenge = undefined;
  return c;
}

export function addCredential(userId: string, cred: StoredCredential): void {
  const u = users.get(userId);
  if (u) u.credentials.push(cred);
}

export function updateCredentialCounter(
  userId: string,
  credentialID: string,
  counter: number,
): void {
  const u = users.get(userId);
  if (!u) return;
  const c = u.credentials.find((c) => c.credentialID === credentialID);
  if (c) c.counter = counter;
}
