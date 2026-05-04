// IAM Privilege Escalation lab — graph-based attack path enumeration.
//
// Catalog drawn from public research:
//   - Spencer Gietzen, "AWS IAM Privilege Escalation" (Rhino Security 2018)
//     https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
//   - "Pacu" framework escalation modules (https://github.com/RhinoSecurityLabs/pacu)
//   - "CloudGoat" attack-path scenarios (Rhino Security)
//   - PowerHuntShares / "Microsoft 365 IAM Privilege Escalation" (NetSPI 2023)
//   - GCP: "GCP IAM Privilege Escalation" — Rhino Security (2020)
//
// The model: an identity graph where nodes are principals (users, roles,
// groups) and edges are permission-derived transitions to another principal
// (or to the synthetic `*` admin node). A path of length >= 1 from your
// starting principal to `*` is a privilege escalation. The lab enumerates
// every such path with breadth-first search.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Provider = "aws" | "azure" | "gcp";

/* ====================================================================== *
 *  Technique catalog                                                     *
 * ====================================================================== */

export interface Technique {
  id: string;
  provider: Provider;
  title: string;
  /** Single-line summary of the action. */
  summary: string;
  /** The exact API permissions an attacker needs. */
  requires: string[];
  /** What the attacker can do once they reach this state. */
  outcome: string;
  /** Mitigation tactic. */
  mitigation: string;
  /** Reference link. */
  reference: string;
  severity: Severity;
}

export const TECHNIQUES: Technique[] = [
  /* ---------------- AWS ---------------- */
  {
    id: "aws-passrole-runinstances",
    provider: "aws",
    title: "iam:PassRole + ec2:RunInstances → instance with admin role",
    summary:
      "Launch an EC2 instance, pass an admin-equivalent role to it, then SSH/SSM in (or read instance metadata) to use that role.",
    requires: ["iam:PassRole", "ec2:RunInstances", "ssm:StartSession OR ec2:GetPasswordData"],
    outcome: "Full access to whatever IAM role you passed to the instance.",
    mitigation:
      "Restrict iam:PassRole with a Condition on iam:PassedToService and a tight resource ARN allowlist. Disable IMDSv1, require IMDSv2 with hop-limit 1.",
    reference:
      "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    severity: "critical",
  },
  {
    id: "aws-passrole-lambda",
    provider: "aws",
    title: "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction",
    summary:
      "Create a Lambda function with an admin role attached, invoke it, exfiltrate temporary credentials from the runtime.",
    requires: [
      "iam:PassRole",
      "lambda:CreateFunction",
      "lambda:InvokeFunction OR lambda:CreateFunctionUrlConfig",
    ],
    outcome:
      "Code execution under the admin role; can call sts:GetCallerIdentity, then any API the role allows.",
    mitigation:
      "Same iam:PassRole condition. Treat lambda:CreateFunction as privileged. Lambda function URLs without auth should not be combinable with PassRole on a powerful role.",
    reference:
      "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    severity: "critical",
  },
  {
    id: "aws-create-access-key",
    provider: "aws",
    title: "iam:CreateAccessKey on another user",
    summary:
      "Mint a long-lived access key for a higher-privileged IAM user.",
    requires: ["iam:CreateAccessKey"],
    outcome: "Persistent credentials for the target user, even if the original credentials are rotated.",
    mitigation:
      "iam:CreateAccessKey should be scoped to ${aws:username} via condition. Better: kill long-lived keys entirely and use IAM Identity Center / OIDC short-lived sessions.",
    reference:
      "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    severity: "critical",
  },
  {
    id: "aws-update-assume-role-policy",
    provider: "aws",
    title: "iam:UpdateAssumeRolePolicy → assume any role",
    summary:
      "Rewrite the trust policy of an admin role to trust your identity, then sts:AssumeRole into it.",
    requires: ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
    outcome: "Become any role whose trust policy you can edit.",
    mitigation:
      "iam:UpdateAssumeRolePolicy should be a denied action even for admin (set in an SCP at the org level). Audit role-trust changes via CloudTrail and alert.",
    reference:
      "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    severity: "critical",
  },
  {
    id: "aws-attach-user-policy",
    provider: "aws",
    title: "iam:AttachUserPolicy → AdministratorAccess on self",
    summary:
      "Attach the AWS-managed AdministratorAccess policy to your own user.",
    requires: ["iam:AttachUserPolicy"],
    outcome: "Self-promotion to admin.",
    mitigation:
      "Deny iam:AttachUserPolicy on the AdministratorAccess managed policy ARN at the SCP layer.",
    reference:
      "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    severity: "critical",
  },
  {
    id: "aws-add-user-to-group",
    provider: "aws",
    title: "iam:AddUserToGroup → join admin group",
    summary:
      "Add yourself to a group whose policies grant admin (e.g. an 'Admins' group).",
    requires: ["iam:AddUserToGroup"],
    outcome: "Inherit every policy attached to the admin group.",
    mitigation:
      "Group-membership changes alarmed via CloudTrail. Avoid group-as-permission-bag pattern; prefer policies attached to roles invoked via SSO.",
    reference:
      "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    severity: "high",
  },
  {
    id: "aws-passrole-codebuild",
    provider: "aws",
    title: "iam:PassRole + codebuild:UpdateProject",
    summary:
      "Modify a CodeBuild project's buildspec / service role to dump credentials in CloudWatch logs.",
    requires: ["iam:PassRole", "codebuild:UpdateProject", "codebuild:StartBuild"],
    outcome: "Steal the CodeBuild project's role credentials at next build.",
    mitigation:
      "Block changes to build infrastructure outside of approved change-management. Pin build roles to least privilege.",
    reference: "https://hackingthe.cloud/aws/exploitation/abuse_codebuild/",
    severity: "high",
  },
  {
    id: "aws-cloudformation-passrole",
    provider: "aws",
    title: "iam:PassRole + cloudformation:CreateStack",
    summary:
      "Create a CloudFormation stack with an admin role; stack template provisions a backdoor.",
    requires: ["iam:PassRole", "cloudformation:CreateStack"],
    outcome:
      "Whatever the admin role can do, the stack can do — including new IAM users, roles, KMS grants.",
    mitigation:
      "CloudFormation stack-level service role should be a deliberately-scoped change-management role, not a generic admin.",
    reference:
      "https://hackingthe.cloud/aws/exploitation/abuse_cloudformation/",
    severity: "high",
  },
  /* ---------------- Azure ---------------- */
  {
    id: "az-add-credentials-to-sp",
    provider: "azure",
    title: "Microsoft.Graph applicationCredential.update → seize Service Principal",
    summary:
      "Add a new client secret or certificate to a higher-privileged Service Principal.",
    requires: ["Application.ReadWrite.OwnedBy OR Application.ReadWrite.All"],
    outcome:
      "Authenticate as the target SP, inheriting all its app roles and permissions (often Global Admin equivalent).",
    mitigation:
      "Lock down Application.ReadWrite.All. Audit appCredential changes via Azure AD audit log. Rotate credentials and require Conditional Access on app-only auth.",
    reference:
      "https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5",
    severity: "critical",
  },
  {
    id: "az-add-owner-to-app",
    provider: "azure",
    title: "Add owner to a privileged Application",
    summary:
      "Make yourself an owner of an Enterprise Application, then mint credentials on its SP.",
    requires: ["Application.ReadWrite.All OR being an owner of the app object"],
    outcome:
      "Full control over the application's SP — same effect as the credentials path.",
    mitigation:
      "Treat application ownership as a privileged role. Audit owner additions.",
    reference:
      "https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5",
    severity: "high",
  },
  {
    id: "az-managed-identity-vm",
    provider: "azure",
    title: "VM Run Command → steal Managed Identity token",
    summary:
      "Use Microsoft.Compute/virtualMachines/runCommand/action on a VM with a powerful managed identity to read its IMDS token.",
    requires: ["Microsoft.Compute/virtualMachines/runCommand/action"],
    outcome:
      "AAD access token for the VM's managed identity, usable for any role assignment it has.",
    mitigation:
      "Restrict runCommand. Strip Managed Identities from VMs that don't need them. Treat IMDS as authentication.",
    reference:
      "https://posts.specterops.io/azurehound-introducing-the-bloodhound-data-collector-for-microsoft-azure-3e2b86f7e4d6",
    severity: "critical",
  },
  /* ---------------- GCP ---------------- */
  {
    id: "gcp-act-as",
    provider: "gcp",
    title: "iam.serviceAccounts.actAs + compute.instances.create",
    summary:
      "Launch a GCE instance running as a privileged service account, then read its metadata token.",
    requires: [
      "iam.serviceAccounts.actAs",
      "compute.instances.create",
    ],
    outcome:
      "Bearer token for the service account's roles (often editor or owner on a project).",
    mitigation:
      "iam.serviceAccounts.actAs should be conditioned with a resource constraint to specific SA names. Org policy: disable default SA on new projects.",
    reference:
      "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/",
    severity: "critical",
  },
  {
    id: "gcp-create-key",
    provider: "gcp",
    title: "iam.serviceAccountKeys.create",
    summary: "Mint a JSON key for a privileged service account.",
    requires: ["iam.serviceAccountKeys.create"],
    outcome: "Persistent credentials for the target SA.",
    mitigation:
      "Org policy: iam.disableServiceAccountKeyCreation. Workload Identity Federation everywhere.",
    reference:
      "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/",
    severity: "critical",
  },
];

/* ====================================================================== *
 *  Identity graph                                                        *
 * ====================================================================== */

export interface Principal {
  id: string;
  kind: "user" | "role" | "group" | "service-account" | "service-principal";
  /** IAM permissions / role assignments held directly. */
  permissions: string[];
  /** Trust policy for roles: principals allowed to AssumeRole. */
  trusts?: string[];
  /** Group membership (AWS users in groups). */
  groups?: string[];
  notes?: string;
}

export interface IamScenario {
  id: string;
  title: string;
  provider: Provider;
  blurb: string;
  startingPrincipal: string;
  principals: Principal[];
  /** Synthetic admin sentinel. A path that ends here is a privesc. */
  adminPolicies: string[];
  /** Optional named real-world scenario this re-creates. */
  reference?: string;
}

/** A directed edge in the privesc graph. */
export interface AttackEdge {
  from: string;
  to: string;
  techniqueId: string;
  detail: string;
}

/** A complete attack path from starting principal to admin. */
export interface AttackPath {
  steps: AttackEdge[];
  endsAtAdmin: boolean;
}

const ADMIN_NODE = "*admin*";

/* ====================================================================== *
 *  Edge derivation                                                       *
 * ====================================================================== */

function principalIsAdmin(p: Principal, adminMarkers: string[]): boolean {
  if (p.permissions.includes("*")) return true;
  return adminMarkers.some((m) => p.permissions.includes(m));
}

function permsEffective(
  p: Principal,
  all: Map<string, Principal>,
): Set<string> {
  const out = new Set(p.permissions);
  for (const g of p.groups ?? []) {
    const gp = all.get(g);
    if (gp) for (const x of gp.permissions) out.add(x);
  }
  return out;
}

/** Build all edges for a graph: which transitions can be made by exercising
 *  a permission held by the source. */
function deriveEdges(scenario: IamScenario): AttackEdge[] {
  const all = new Map(scenario.principals.map((p) => [p.id, p]));
  const edges: AttackEdge[] = [];

  for (const src of scenario.principals) {
    const perms = permsEffective(src, all);

    /* AWS PassRole + RunInstances / Lambda / CodeBuild / CloudFormation */
    if (perms.has("iam:PassRole")) {
      for (const target of scenario.principals) {
        if (target.id === src.id) continue;
        if (target.kind !== "role") continue;
        if (perms.has("ec2:RunInstances")) {
          edges.push({
            from: src.id,
            to: target.id,
            techniqueId: "aws-passrole-runinstances",
            detail: `Run an EC2 instance with role ${target.id} attached, then read IMDS.`,
          });
        }
        if (perms.has("lambda:CreateFunction") && perms.has("lambda:InvokeFunction")) {
          edges.push({
            from: src.id,
            to: target.id,
            techniqueId: "aws-passrole-lambda",
            detail: `Create a Lambda fn with role ${target.id}, invoke it.`,
          });
        }
        if (perms.has("codebuild:UpdateProject") && perms.has("codebuild:StartBuild")) {
          edges.push({
            from: src.id,
            to: target.id,
            techniqueId: "aws-passrole-codebuild",
            detail: `Edit a CodeBuild project to assume role ${target.id}, dump creds in logs.`,
          });
        }
        if (perms.has("cloudformation:CreateStack")) {
          edges.push({
            from: src.id,
            to: target.id,
            techniqueId: "aws-cloudformation-passrole",
            detail: `Create a CloudFormation stack using ${target.id} as the service role.`,
          });
        }
      }
    }

    /* iam:CreateAccessKey on another user */
    if (perms.has("iam:CreateAccessKey")) {
      for (const target of scenario.principals) {
        if (target.id === src.id) continue;
        if (target.kind !== "user") continue;
        edges.push({
          from: src.id,
          to: target.id,
          techniqueId: "aws-create-access-key",
          detail: `Mint a new access key for ${target.id}.`,
        });
      }
    }

    /* iam:UpdateAssumeRolePolicy + sts:AssumeRole */
    if (perms.has("iam:UpdateAssumeRolePolicy") && perms.has("sts:AssumeRole")) {
      for (const target of scenario.principals) {
        if (target.kind !== "role" || target.id === src.id) continue;
        edges.push({
          from: src.id,
          to: target.id,
          techniqueId: "aws-update-assume-role-policy",
          detail: `Rewrite trust policy of ${target.id} to allow ${src.id}, then sts:AssumeRole.`,
        });
      }
    }

    /* iam:AttachUserPolicy on self → admin */
    if (perms.has("iam:AttachUserPolicy")) {
      edges.push({
        from: src.id,
        to: ADMIN_NODE,
        techniqueId: "aws-attach-user-policy",
        detail: `Attach AdministratorAccess to ${src.id}.`,
      });
    }

    /* iam:AddUserToGroup → if any group has admin perms, edge to admin */
    if (perms.has("iam:AddUserToGroup")) {
      for (const target of scenario.principals) {
        if (target.kind !== "group") continue;
        const adminGroup = target.permissions.includes("*");
        if (adminGroup) {
          edges.push({
            from: src.id,
            to: ADMIN_NODE,
            techniqueId: "aws-add-user-to-group",
            detail: `Add ${src.id} to ${target.id} (admin group).`,
          });
        } else {
          edges.push({
            from: src.id,
            to: target.id,
            techniqueId: "aws-add-user-to-group",
            detail: `Add ${src.id} to ${target.id}.`,
          });
        }
      }
    }

    /* Azure: Application.ReadWrite.All → seize an SP */
    if (
      perms.has("Application.ReadWrite.All") ||
      perms.has("Application.ReadWrite.OwnedBy")
    ) {
      for (const target of scenario.principals) {
        if (target.kind !== "service-principal" || target.id === src.id) continue;
        edges.push({
          from: src.id,
          to: target.id,
          techniqueId: "az-add-credentials-to-sp",
          detail: `Add a client-secret to ${target.id}'s app registration, sign in as it.`,
        });
      }
    }

    /* Azure: VM Run Command → MSI token */
    if (perms.has("Microsoft.Compute/virtualMachines/runCommand/action")) {
      for (const target of scenario.principals) {
        if (target.kind !== "service-principal" || target.id === src.id) continue;
        edges.push({
          from: src.id,
          to: target.id,
          techniqueId: "az-managed-identity-vm",
          detail: `runCommand on a VM bound to ${target.id} (MI), read IMDS token.`,
        });
      }
    }

    /* GCP actAs + compute.instances.create */
    if (perms.has("iam.serviceAccounts.actAs") && perms.has("compute.instances.create")) {
      for (const target of scenario.principals) {
        if (target.kind !== "service-account" || target.id === src.id) continue;
        edges.push({
          from: src.id,
          to: target.id,
          techniqueId: "gcp-act-as",
          detail: `Launch a GCE VM as ${target.id}, read metadata token.`,
        });
      }
    }

    /* GCP service-account-key creation */
    if (perms.has("iam.serviceAccountKeys.create")) {
      for (const target of scenario.principals) {
        if (target.kind !== "service-account" || target.id === src.id) continue;
        edges.push({
          from: src.id,
          to: target.id,
          techniqueId: "gcp-create-key",
          detail: `Create JSON key for ${target.id}.`,
        });
      }
    }

    /* Implicit: if you ARE a principal that already holds admin, edge to ADMIN */
    if (principalIsAdmin(src, scenario.adminPolicies)) {
      edges.push({
        from: src.id,
        to: ADMIN_NODE,
        techniqueId: "implicit-admin",
        detail: `${src.id} already holds an admin-equivalent permission.`,
      });
    }
  }

  // De-dup
  const seen = new Set<string>();
  return edges.filter((e) => {
    const k = `${e.from}->${e.to}#${e.techniqueId}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/* ====================================================================== *
 *  Path enumeration                                                      *
 * ====================================================================== */

export function enumerateAttackPaths(scenario: IamScenario): {
  edges: AttackEdge[];
  paths: AttackPath[];
} {
  const edges = deriveEdges(scenario);
  const adj = new Map<string, AttackEdge[]>();
  for (const e of edges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from)!.push(e);
  }

  const paths: AttackPath[] = [];
  const start = scenario.startingPrincipal;
  const MAX_DEPTH = 6;
  const MAX_PATHS = 25;

  function dfs(node: string, current: AttackEdge[], visited: Set<string>) {
    if (paths.length >= MAX_PATHS) return;
    if (current.length > MAX_DEPTH) return;
    if (node === ADMIN_NODE) {
      paths.push({ steps: [...current], endsAtAdmin: true });
      return;
    }
    const next = adj.get(node) ?? [];
    for (const e of next) {
      if (visited.has(e.to)) continue;
      visited.add(e.to);
      current.push(e);
      dfs(e.to, current, visited);
      current.pop();
      visited.delete(e.to);
    }
  }

  dfs(start, [], new Set([start]));
  // Sort by length (shortest path = most direct privesc)
  paths.sort((a, b) => a.steps.length - b.steps.length);
  return { edges, paths };
}

/* ====================================================================== *
 *  Scenarios                                                              *
 * ====================================================================== */

export const SCENARIOS: IamScenario[] = [
  {
    id: "aws-developer-passrole",
    provider: "aws",
    title: "AWS: developer with iam:PassRole + ec2:RunInstances",
    blurb:
      "A developer user is granted iam:PassRole + ec2:RunInstances + ssm:StartSession 'for debugging'. There's an unrelated EC2-Admin role. The developer can launch an instance carrying that role and SSM in.",
    startingPrincipal: "user/dev-alice",
    adminPolicies: ["*"],
    reference:
      "Rhino Security Labs, AWS Privilege Escalation Methods (2018) — Method 8",
    principals: [
      {
        id: "user/dev-alice",
        kind: "user",
        permissions: [
          "iam:PassRole",
          "ec2:RunInstances",
          "ssm:StartSession",
          "ec2:DescribeInstances",
        ],
      },
      {
        id: "role/EC2-Admin",
        kind: "role",
        permissions: ["*"],
        trusts: ["ec2.amazonaws.com"],
        notes:
          "Powerful role intended for admin EC2 instances; trust policy is the EC2 service principal so anyone who can pass it to an instance becomes admin.",
      },
      {
        id: "role/Read-Only",
        kind: "role",
        permissions: ["s3:Get*", "s3:List*"],
        trusts: ["ec2.amazonaws.com"],
      },
    ],
  },
  {
    id: "aws-passrole-lambda",
    provider: "aws",
    title: "AWS: PassRole + Lambda function-URL chain",
    blurb:
      "A user has iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction. They create a Lambda with an admin role and invoke it.",
    startingPrincipal: "user/dev-bob",
    adminPolicies: ["*"],
    reference:
      "Rhino Security Labs, AWS Privilege Escalation Methods (2018) — Method 9",
    principals: [
      {
        id: "user/dev-bob",
        kind: "user",
        permissions: [
          "iam:PassRole",
          "lambda:CreateFunction",
          "lambda:InvokeFunction",
        ],
      },
      {
        id: "role/Lambda-Admin",
        kind: "role",
        permissions: ["*"],
        trusts: ["lambda.amazonaws.com"],
      },
    ],
  },
  {
    id: "aws-add-user-to-group",
    provider: "aws",
    title: "AWS: iam:AddUserToGroup + admin group",
    blurb:
      "A user has iam:AddUserToGroup. There's an 'Admins' group with AdministratorAccess attached. One API call away.",
    startingPrincipal: "user/junior-eve",
    adminPolicies: ["*"],
    reference:
      "Rhino Security Labs, AWS Privilege Escalation Methods (2018) — Method 5",
    principals: [
      {
        id: "user/junior-eve",
        kind: "user",
        permissions: ["iam:AddUserToGroup", "iam:ListGroups"],
      },
      {
        id: "group/Admins",
        kind: "group",
        permissions: ["*"],
      },
    ],
  },
  {
    id: "aws-update-trust-policy",
    provider: "aws",
    title: "AWS: rewrite a role's trust policy",
    blurb:
      "A user has iam:UpdateAssumeRolePolicy + sts:AssumeRole. They rewrite an admin role's trust policy to trust themselves, then assume it.",
    startingPrincipal: "user/contractor-carl",
    adminPolicies: ["*"],
    reference:
      "Rhino Security Labs, AWS Privilege Escalation Methods (2018) — Method 11",
    principals: [
      {
        id: "user/contractor-carl",
        kind: "user",
        permissions: ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
      },
      {
        id: "role/Org-Admin",
        kind: "role",
        permissions: ["*"],
        trusts: ["specific-internal-only-role"],
      },
    ],
  },
  {
    id: "aws-multi-hop",
    provider: "aws",
    title: "AWS: multi-hop chain (user → group → role → admin)",
    blurb:
      "Demonstrates path enumeration. Starting user has iam:AddUserToGroup. The group has iam:PassRole + ec2:RunInstances. The reachable admin role is two hops away.",
    startingPrincipal: "user/intern-irene",
    adminPolicies: ["*"],
    reference: "Synthetic — illustrates path-finding through indirect permissions.",
    principals: [
      {
        id: "user/intern-irene",
        kind: "user",
        permissions: ["iam:AddUserToGroup", "iam:ListGroups"],
        groups: [],
      },
      {
        id: "group/Engineers",
        kind: "group",
        permissions: ["iam:PassRole", "ec2:RunInstances", "ssm:StartSession"],
      },
      {
        id: "role/Power-User-Role",
        kind: "role",
        permissions: ["*"],
        trusts: ["ec2.amazonaws.com"],
      },
    ],
  },
  {
    id: "azure-app-readwrite",
    provider: "azure",
    title: "Azure: Application.ReadWrite.All → Global Admin SP",
    blurb:
      "A user has Application.ReadWrite.All on Microsoft Graph. There's a Service Principal with Directory.ReadWrite.All / Global Admin role. Add a client secret to that SP and sign in as it.",
    startingPrincipal: "user/devops-david",
    adminPolicies: ["*", "Directory.ReadWrite.All"],
    reference:
      "Andy Robbins (SpecterOps), 'Azure Privilege Escalation via Service Principal Abuse' (2021)",
    principals: [
      {
        id: "user/devops-david",
        kind: "user",
        permissions: ["Application.ReadWrite.All"],
      },
      {
        id: "sp/CI-Pipeline",
        kind: "service-principal",
        permissions: ["Directory.ReadWrite.All", "*"],
      },
    ],
  },
  {
    id: "gcp-actas-compute",
    provider: "gcp",
    title: "GCP: actAs + compute.instances.create → owner SA",
    blurb:
      "A user holds iam.serviceAccounts.actAs on a default-named SA + compute.instances.create. The SA has roles/owner. Boot a VM as that SA and read its metadata token.",
    startingPrincipal: "user/data-scientist",
    adminPolicies: ["*", "roles/owner"],
    reference:
      "Rhino Security Labs, GCP Privilege Escalation Part 1 (2020)",
    principals: [
      {
        id: "user/data-scientist",
        kind: "user",
        permissions: [
          "iam.serviceAccounts.actAs",
          "compute.instances.create",
        ],
      },
      {
        id: "sa/owner-sa",
        kind: "service-account",
        permissions: ["roles/owner", "*"],
      },
    ],
  },
];
