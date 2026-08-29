# C2C Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Patch the confirmed C2C security findings without removing capabilities, adding provider restrictions, adding content redaction, adding an execution sandbox/firewall, or changing the zero-touch user experience.

**Architecture:** Keep the existing read-only MCP + OAuth + Cloudflare tunnel + Codex execution split. Harden the existing trust boundaries in place: safely render OAuth HTML, make OAuth scope/resource handling fail-safe, apply existing sensitive-path policy consistently to Git metadata, remove public workspace fingerprints, and replace unauthenticated automatic `git pull` updates with a signed Ed25519 update channel that remains fully automatic and rolls back on failure.

**Tech Stack:** Node.js >=20, TypeScript 5.9, Express 5, MCP TypeScript SDK 1.30.0, Commander 14, Vitest 3, pnpm 11.24, Node `crypto` Ed25519, Git.

**Spec:** `docs/security-hardening-spec.md`

## Global Constraints

- Cloudflare remains supported and enabled; do not replace or remove Quick Tunnel.
- All approved cloud providers receive the same bridge capabilities; no provider capability profiles.
- Workspace access remains allow-by-default except existing `IgnoreRules` / `.c2cignore` path denials.
- Do not add content-level secret scanning or redaction.
- Arbitrary HTTPS OAuth clients and localhost HTTP development clients remain supported.
- Keep all current read-only MCP tools and their information content except sensitive paths already forbidden by policy.
- Do not add C2C plan filtering, command sandboxing, or an execution allowlist; local Codex/agent policy stays authoritative.
- Updates remain fully automatic for end users; no update confirmation prompt.
- Do not add transmission audit logging.
- Provider sessions continue sharing project/workspace execution state.
- Do not add user-facing security profiles or mandatory configuration.
- MCP remains read-only: no write/delete/shell/commit/install tools.
- Use TDD for every behavioral change; each task ends with a focused test pass and a commit.
- Do not silently broaden scope beyond `docs/security-hardening-spec.md`.

---

## File Structure / Ownership Map

### Create

- `src/security/html.ts` — single-purpose HTML escaping helper for server-rendered authorization UI.
- `src/update/trust.ts` — update-channel constants, pinned public-key loading, manifest types.
- `src/update/channel.ts` — canonical manifest parsing, Ed25519 verification, remote/channel verification.
- `src/update/transaction.ts` — verified fast-forward update, install/build, rollback, skill reinstall/restart orchestration.
- `scripts/generate-update-key.mjs` — one-time Ed25519 keypair generator for maintainers.
- `scripts/publish-update-channel.mjs` — signs the current `main` commit and publishes `latest.json`/`latest.sig` to `c2c-update-channel` using Git plumbing.
- `.github/workflows/publish-update-channel.yml` — test/build gate + signed channel publication on every `main` push.
- `security/update-public-key.pem` — generated Ed25519 public key; private key never enters Git.
- `tests/update-channel.test.ts` — manifest/signature/channel validation.
- `tests/update-transaction.test.ts` — update success, tamper rejection, fast-forward enforcement, rollback.

### Modify

- `src/auth/oauth.ts` — safe pairing-page rendering, neutral client identity, strict response headers, resource validation.
- `src/auth/store.ts` — replace invalid-scope fallback with explicit scope-resolution result.
- `src/bridge/server.ts` — request-independent base URL, loopback-only proxy trust, minimal public health.
- `src/bridge/runtime.ts` — authenticated local bridge identity check via `/admin/info`.
- `src/workspace/git.ts` — apply `IgnoreRules` to `gitStatus`, including rename/copy provenance.
- `src/mcp/server.ts` — pass `Workspace` to `gitStatus`.
- `src/cli/index.ts` — use secure update-channel library; add `c2c update` command.
- `skill/SKILL.md` — call `c2c update` rather than raw `git pull`; use frozen lockfile installs.
- `package.json` — pin MCP SDK to current resolved version `1.30.0`.
- `pnpm-lock.yaml` — update only if pnpm changes lock metadata after exact-version pin.
- `README.md`, `README.zh-CN.md` — deterministic install commands and accurate security/update statements.
- `docs/security.md` — corrected trust boundaries and accepted residual risks.
- `docs/architecture.md` — signed update-channel flow and minimal public health endpoint.
- `tests/oauth.test.ts` — XSS/CSP/client identity/scope/resource regression coverage.
- `tests/git.test.ts` — sensitive status filtering and rename/copy coverage.
- `tests/mcp-integration.test.ts` — verify MCP `git_status` does not expose denied paths.
- `tests/port.test.ts` — public health privacy + authenticated local bridge identity.

---

### Task 1: Harden OAuth authorization HTML without changing the pairing flow

**Files:**
- Create: `src/security/html.ts`
- Modify: `src/auth/oauth.ts`
- Test: `tests/oauth.test.ts`

**Interfaces:**
- Produces: `escapeHtml(value: string): string`
- Produces inside `oauth.ts`: `setAuthorizationPageHeaders(res: Response): void`
- `pairingPage()` gains `clientName` and `redirectOrigin` inputs but continues returning a complete HTML string.

- [ ] **Step 1: Add failing OAuth rendering/security-header tests**

Add tests that start a bridge whose `.c2c.json` contains a hostile name and register a client with a hostile `client_name`:

```ts
write(root, ".c2c.json", JSON.stringify({
  name: `<img src=x onerror="globalThis.pwned=1"> & \"project\"`,
}));
```

Register:

```ts
{
  client_name: `<script>globalThis.pwned=1</script> Reviewer`,
  redirect_uris: ["https://agent.example/callback"]
}
```

Assertions on `GET /oauth/authorize`:

```ts
expect(html).not.toContain("<script>globalThis.pwned=1</script>");
expect(html).not.toContain("<img src=x");
expect(html).toContain("&lt;script&gt;globalThis.pwned=1&lt;/script&gt; Reviewer");
expect(html).toContain("&lt;img src=x onerror=&quot;globalThis.pwned=1&quot;&gt;");
expect(html).toContain("https://agent.example");
expect(response.headers.get("content-security-policy")).toBe(
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'"
);
expect(response.headers.get("cache-control")).toBe("no-store");
expect(response.headers.get("referrer-policy")).toBe("no-referrer");
expect(response.headers.get("x-content-type-options")).toBe("nosniff");
expect(response.headers.get("x-frame-options")).toBe("DENY");
```

Also assert the page no longer hard-codes "ChatGPT is requesting access" and instead identifies the registered client.

- [ ] **Step 2: Run the focused test and verify failure**

Run:

```bash
corepack pnpm vitest run tests/oauth.test.ts
```

Expected: new hostile-name/client-name and header assertions fail against current code.

- [ ] **Step 3: Implement `escapeHtml`**

Create `src/security/html.ts`:

```ts
const HTML_ESCAPE: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => HTML_ESCAPE[ch]);
}
```

Do not add a templating dependency.

- [ ] **Step 4: Make pairing-page rendering safe and provider-neutral**

In `src/auth/oauth.ts`:

1. import `escapeHtml`;
2. extend `pairingPage` input with `clientName: string` and `redirectOrigin: string`;
3. escape `PRODUCT_NAME`, `clientName`, `redirectOrigin`, `workspaceName`, `requestId`, error text, and scope label text before interpolation;
4. render this meaning without changing the form mechanics:

```text
<clientName> is requesting read-only access to workspace <workspaceName>.
Redirect destination: <redirectOrigin>
```

Use `new URL(request.redirectUri).origin` for `redirectOrigin`.

- [ ] **Step 5: Apply strict headers to every authorization HTML response**

Add in `oauth.ts`:

```ts
function setAuthorizationPageHeaders(res: Response): void {
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
}
```

Call it before both initial pairing-page responses and pairing-error page responses.

- [ ] **Step 6: Verify the normal flow remains unchanged**

Run:

```bash
corepack pnpm vitest run tests/oauth.test.ts
```

Expected: all OAuth tests pass, including the existing full pairing + PKCE + MCP call.

- [ ] **Step 7: Commit**

```bash
git add src/security/html.ts src/auth/oauth.ts tests/oauth.test.ts
git commit -m "fix: harden OAuth pairing page rendering"
```

---

### Task 2: Fix OAuth scope escalation, target validation, and request-derived issuer risk

**Files:**
- Modify: `src/auth/store.ts`
- Modify: `src/auth/oauth.ts`
- Modify: `src/bridge/server.ts`
- Test: `tests/oauth.test.ts`

**Interfaces:**
- Replace: `filterScopes(requested?: string): string[]`
- Produce:

```ts
export type ScopeResolution =
  | { ok: true; scopes: Scope[] }
  | { ok: false; error: "invalid_scope" };

export function resolveScopes(requested?: string): ScopeResolution;
```

- [ ] **Step 1: Add failing scope tests**

Add HTTP-level tests for these exact cases:

```text
scope omitted                 -> authorization page, all existing default scopes
scope="workspace.read"        -> only workspace.read
scope="workspace.read nope"   -> workspace.read only
scope="totally.invalid"       -> redirect with error=invalid_scope; no pairing page
```

For the invalid-only request, assert the response is a redirect to the already-registered redirect URI containing `error=invalid_scope` and preserving `state`.

- [ ] **Step 2: Add failing OAuth resource tests**

Add:

```text
resource omitted                         -> accepted
resource=<base>/mcp                      -> accepted
resource=<base>/mcp/                     -> accepted after trailing-slash normalization
resource=https://attacker.example/mcp    -> invalid_target
resource=not-a-url                       -> invalid_target
```

No pending pairing page may be created for invalid target requests.

- [ ] **Step 3: Add a base-URL Host-header regression test**

Before starting a tunnel, request discovery metadata using hostile `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto` headers. Assert issuer/resource URLs still use the bridge's known local address/actual port rather than attacker-controlled header values.

- [ ] **Step 4: Run focused tests and confirm failure**

```bash
corepack pnpm vitest run tests/oauth.test.ts
```

- [ ] **Step 5: Implement `resolveScopes`**

Use exactly these semantics:

```ts
export function resolveScopes(requested: string | undefined): ScopeResolution {
  if (!requested || requested.trim() === "") {
    return { ok: true, scopes: [...SUPPORTED_SCOPES] };
  }
  const asked = requested.split(/[\s+]+/).filter(Boolean);
  const granted = asked.filter(
    (scope): scope is Scope => (SUPPORTED_SCOPES as readonly string[]).includes(scope)
  );
  if (granted.length === 0) return { ok: false, error: "invalid_scope" };
  return { ok: true, scopes: [...new Set(granted)] };
}
```

Unknown extras are ignored when at least one supported scope is present; missing scope still means all scopes.

- [ ] **Step 6: Reject invalid scope and resource before storing pending auth state**

In `GET /oauth/authorize`:

1. call `resolveScopes(query.scope)`;
2. if not `ok`, use the existing `fail()` redirect with `invalid_scope`;
3. compute canonical MCP resource from `deps.getBaseUrl(req)`;
4. if `query.resource` exists, parse it with `new URL` and compare normalized strings after removing one trailing slash; on malformed/mismatch, `fail("invalid_target", "resource must identify this bridge MCP endpoint")`;
5. only create/store `PendingAuthRequest` after all validation succeeds.

- [ ] **Step 7: Remove request headers from local base-URL authority**

In `src/bridge/server.ts`, make `getBaseUrl` return:

```ts
if (publicBaseUrl) return publicBaseUrl;
return `http://${host}:${port}`;
```

Do not use `req.protocol` or `req.get("host")` for issuer/resource construction.

Change proxy trust from global trust to loopback-only trust:

```ts
app.set("trust proxy", (ip: string) =>
  ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1"
);
```

- [ ] **Step 8: Run OAuth tests**

```bash
corepack pnpm vitest run tests/oauth.test.ts
```

Expected: all old and new tests pass.

- [ ] **Step 9: Commit**

```bash
git add src/auth/store.ts src/auth/oauth.ts src/bridge/server.ts tests/oauth.test.ts
git commit -m "fix: tighten OAuth scope and resource validation"
```

---

### Task 3: Apply the existing sensitive-path policy to `git_status`

**Files:**
- Modify: `src/workspace/git.ts`
- Modify: `src/mcp/server.ts`
- Test: `tests/git.test.ts`
- Test: `tests/mcp-integration.test.ts`

**Interfaces:**
- Change: `gitStatus(root: string)` -> `gitStatus(target: GitTarget)`.
- Existing `GitStatusResult` shape remains unchanged.

- [ ] **Step 1: Add failing unit tests for sensitive status paths**

Create staged, unstaged, untracked, conflicted, and rename cases containing:

```text
.env
.npmrc
credentials.json
private/.ssh/config
custom-secret.txt (denied by .c2cignore)
```

For each case, assert sensitive names are absent while safe entries remain present.

Include both rename directions:

```text
.npmrc -> visible.txt
visible.txt -> .env.production
```

If either side is sensitive, neither side may appear in returned status.

- [ ] **Step 2: Add failing MCP integration coverage**

Call `git_status` through the MCP transport with a valid `git.read` token and assert denied paths are absent from the JSON tool result.

- [ ] **Step 3: Run the focused tests and confirm failure**

```bash
corepack pnpm vitest run tests/git.test.ts tests/mcp-integration.test.ts
```

- [ ] **Step 4: Make status parsing path-safe**

Change `gitStatus` to derive `root` + `ignoreRules` exactly like `gitDiff`:

```ts
export function gitStatus(target: GitTarget): GitStatusResult {
  const root = typeof target === "string" ? target : target.root;
  const ignoreRules =
    typeof target === "object" && target.ignoreRules
      ? target.ignoreRules
      : new IgnoreRules(root);
  // ...
}
```

Use porcelain-v2 NUL mode so filenames are not security-parsed through shell-style quoting:

```ts
runGit(root, ["status", "--porcelain=v2", "--branch", "-z", "--", "."])
```

Parse NUL records. For type `2` rename/copy records, consume the following original-path NUL field. Before adding any path to `staged`, `unstaged`, `untracked`, or `conflicted`, require `!ignoreRules.isSensitive(path)`. For rename/copy require both old and new path to be non-sensitive.

Do not filter or alter branch/upstream/ahead/behind metadata.

- [ ] **Step 5: Pass the `Workspace` object from MCP**

Change:

```ts
gitStatus(workspace.root)
```

to:

```ts
gitStatus(workspace)
```

This ensures `.c2cignore` and the centralized sensitive rules are reused.

- [ ] **Step 6: Run focused tests**

```bash
corepack pnpm vitest run tests/git.test.ts tests/mcp-integration.test.ts
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/workspace/git.ts src/mcp/server.ts tests/git.test.ts tests/mcp-integration.test.ts
git commit -m "fix: hide denied paths from git status"
```

---

### Task 4: Remove the workspace fingerprint from the public health endpoint

**Files:**
- Modify: `src/bridge/server.ts`
- Modify: `src/bridge/runtime.ts`
- Test: `tests/port.test.ts`

**Interfaces:**

```ts
export interface HealthPayload {
  service: string;
  version: string;
  status: string;
}

export interface AdminProbePayload extends HealthPayload {
  workspaceId: string;
}

export async function probeBridge(port: number, timeoutMs?: number): Promise<HealthPayload | null>;
export async function probeRuntimeState(state: RuntimeState, timeoutMs?: number): Promise<AdminProbePayload | null>;
```

- [ ] **Step 1: Replace current port test expectations with privacy + authenticated identity tests**

Assert:

```ts
const health = await probeBridge(bridge.port);
expect(health?.service).toBe("codex-with-chatgpt");
expect("workspaceId" in (health ?? {})).toBe(false);
```

Then create a runtime-state-backed bridge and assert `findLiveBridge(workspace.id)` still finds only the correct workspace.

Also directly request `/admin/info` without a token and with simulated proxy headers and assert 404.

- [ ] **Step 2: Run and verify failure**

```bash
corepack pnpm vitest run tests/port.test.ts
```

- [ ] **Step 3: Make `/health` truly public-minimal**

Return only:

```ts
{ service: SERVICE_NAME, version: VERSION, status: "ok" }
```

Do not change `Workspace.id` itself.

- [ ] **Step 4: Add authenticated local runtime probing**

`probeRuntimeState(state)` must call:

```text
GET http://127.0.0.1:<state.port>/admin/info
Authorization: Bearer <state.adminToken>
```

with timeout and require `service === SERVICE_NAME`.

Change `findLiveBridge(workspaceId)` to:

1. read the 0600 runtime state for that workspace ID;
2. call `probeRuntimeState(state)`;
3. return state only if authenticated admin info reports the same `workspaceId`.

The public `probeBridge()` remains useful only for service/health detection and no longer authenticates workspace identity.

- [ ] **Step 5: Run port tests**

```bash
corepack pnpm vitest run tests/port.test.ts
```

- [ ] **Step 6: Commit**

```bash
git add src/bridge/server.ts src/bridge/runtime.ts tests/port.test.ts
git commit -m "fix: remove workspace identity from public health"
```

---

### Task 5: Make dependency installation deterministic without reducing runtime capability

**Files:**
- Modify: `package.json`
- Modify if generated: `pnpm-lock.yaml`
- Modify: `skill/SKILL.md`
- Modify: `README.md`
- Modify: `README.zh-CN.md`

**Interfaces:** none.

- [ ] **Step 1: Pin the MCP SDK to the already-resolved baseline version**

Change only:

```json
"@modelcontextprotocol/sdk": "1.30.0"
```

Do not opportunistically upgrade other dependencies in this task.

- [ ] **Step 2: Reinstall strictly from the existing lockfile**

Run:

```bash
corepack pnpm install --frozen-lockfile
```

Expected: success. If pnpm reports that the manifest and lockfile differ because of the exact-version change, run one intentional lockfile refresh:

```bash
corepack pnpm install --lockfile-only
corepack pnpm install --frozen-lockfile
```

Review the lockfile diff and require that it changes only the importer specifier/metadata needed for `@modelcontextprotocol/sdk` and does not upgrade resolved packages.

- [ ] **Step 3: Change automated installation instructions to frozen-lockfile mode**

Replace automated `corepack pnpm install` / `pnpm install` instructions in `skill/SKILL.md`, `README.md`, and `README.zh-CN.md` with:

```bash
corepack pnpm install --frozen-lockfile
```

Keep build commands unchanged.

- [ ] **Step 4: Verify build/test/typecheck**

```bash
corepack pnpm typecheck
corepack pnpm build
corepack pnpm test
```

Expected: all succeed.

- [ ] **Step 5: Commit**

```bash
git add package.json pnpm-lock.yaml skill/SKILL.md README.md README.zh-CN.md
git commit -m "chore: make dependency installs deterministic"
```

---

### Task 6: Implement signed Ed25519 update-channel verification

**Files:**
- Create: `src/update/trust.ts`
- Create: `src/update/channel.ts`
- Create: `tests/update-channel.test.ts`
- Create later in Task 8: `security/update-public-key.pem`

**Interfaces:**

```ts
export interface UpdateManifest {
  schema: 1;
  repository: string;
  branch: "main";
  commit: string;
  publishedAt: string;
}

export type UpdateCheckResult =
  | { ok: true; updateAvailable: boolean; localCommit: string; remoteCommit: string; manifest: UpdateManifest }
  | { ok: false; reason: "offline" | "unsigned" | "invalid_signature" | "invalid_manifest" | "channel_not_ready" | "git_error"; message: string };

export function canonicalManifestBytes(manifest: UpdateManifest): Buffer;
export function verifyManifest(manifestText: string, signatureText: string, publicKeyPem: string): UpdateManifest;
export function checkVerifiedUpdate(opts: { repoRoot: string; remote?: string; publicKeyPem?: string }): UpdateCheckResult;
```

Production constants:

```ts
export const UPDATE_REPOSITORY = "LeonAI-DO-YLCS/codex-with-chatgpt";
export const UPDATE_BRANCH = "main";
export const UPDATE_CHANNEL_REMOTE_REF = "refs/heads/c2c-update-channel";
export const UPDATE_CHANNEL_LOCAL_REF = "refs/c2c/update-channel";
```

- [ ] **Step 1: Write pure cryptographic tests first**

In the test, use `generateKeyPairSync("ed25519")` to generate an ephemeral keypair. Build a valid manifest, canonicalize it, sign it, and assert verification succeeds.

Negative cases must include:

- one-byte manifest modification;
- malformed Base64 signature;
- valid signature from a different key;
- wrong `schema`;
- wrong repository;
- wrong branch;
- malformed/non-40-hex commit;
- non-UTC/invalid `publishedAt`.

- [ ] **Step 2: Write a local-Git integration test for channel verification**

Use temporary local repositories only; no network. Create:

1. a working repository representing the installed checkout;
2. a bare repository representing `origin`;
3. `main` at commit A then commit B;
4. a `c2c-update-channel` branch containing signed `latest.json`/`latest.sig` for B.

Point the checkout's `origin` to the bare repo and assert `checkVerifiedUpdate()` returns B and `updateAvailable: true`.

Then mutate channel contents without the signing key and assert `ok: false`.

- [ ] **Step 3: Run tests and verify they fail before implementation**

```bash
corepack pnpm vitest run tests/update-channel.test.ts
```

- [ ] **Step 4: Implement canonical manifest serialization**

`canonicalManifestBytes()` must emit exactly this property order and one LF:

```ts
return Buffer.from(
  JSON.stringify({
    schema: manifest.schema,
    repository: manifest.repository,
    branch: manifest.branch,
    commit: manifest.commit,
    publishedAt: manifest.publishedAt,
  }) + "\n",
  "utf8"
);
```

Verification must compare the received `latest.json` bytes to the canonical serialization of its parsed object; non-canonical JSON is rejected. This prevents signing/verification ambiguity.

- [ ] **Step 5: Implement Ed25519 verification with Node built-ins**

Use:

```ts
import { verify } from "node:crypto";
verify(null, canonicalBytes, publicKeyPem, Buffer.from(signatureText.trim(), "base64"));
```

No third-party crypto dependency.

- [ ] **Step 6: Implement remote channel checks**

Use Git commands with `GIT_TERMINAL_PROMPT=0` and bounded timeouts:

```text
git rev-parse HEAD
git ls-remote origin refs/heads/main refs/heads/c2c-update-channel
git fetch --quiet --force --no-tags origin refs/heads/c2c-update-channel:refs/c2c/update-channel
git show refs/c2c/update-channel:latest.json
git show refs/c2c/update-channel:latest.sig
```

Verification order is mandatory:

1. both remote refs exist;
2. signature verifies under current installed key;
3. manifest schema/repository/branch/timestamp/SHA validate;
4. signed manifest commit equals remote `main` SHA;
5. only then may result report an actionable update.

If `main` moved but the signed channel has not yet caught up, return `channel_not_ready`, do not mark the daily check successful, and do not update.

- [ ] **Step 7: Run tests**

```bash
corepack pnpm vitest run tests/update-channel.test.ts
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add src/update/trust.ts src/update/channel.ts tests/update-channel.test.ts
git commit -m "feat: verify automatic updates with signed channel"
```

---

### Task 7: Make automatic updates transactional, exact-target, and rollback-safe

**Files:**
- Create: `src/update/transaction.ts`
- Create: `tests/update-transaction.test.ts`
- Modify: `src/cli/index.ts`
- Modify: `skill/SKILL.md`

**Interfaces:**

```ts
export interface UpdateTransactionOptions {
  repoRoot: string;
  workspaceRoot: string;
  remote?: string;
  publicKeyPem?: string;
}

export type UpdateTransactionResult =
  | { ok: true; updated: boolean; from: string; to: string; stashRef?: string }
  | { ok: false; stage: "verify" | "fetch" | "fast_forward" | "install" | "build" | "rollback" | "post_update"; message: string; rolledBack: boolean };

export function performVerifiedUpdate(opts: UpdateTransactionOptions): UpdateTransactionResult;
```

- [ ] **Step 1: Write transaction tests using temp Git repositories**

Cover all exact behaviors:

1. valid signed A -> B fast-forward succeeds;
2. unsigned/tampered channel changes nothing;
3. signed target not equal to remote `main` changes nothing;
4. non-fast-forward signed target is rejected;
5. dirty checkout is stashed with untracked files included before mutation;
6. simulated install failure resets HEAD to A and reports `rolledBack: true`;
7. simulated build failure resets HEAD to A and reports `rolledBack: true`;
8. post-update restart hooks are never invoked after failed verification/install/build;
9. successful update targets the exact signed SHA, not a later moving branch head.

Make external command execution injectable in tests rather than invoking real package installs. The production implementation uses the real runner; tests use a deterministic fake for install/build/restart stages.

- [ ] **Step 2: Run and confirm failure**

```bash
corepack pnpm vitest run tests/update-transaction.test.ts
```

- [ ] **Step 3: Re-verify before every update**

`performVerifiedUpdate()` starts by calling `checkVerifiedUpdate()`; it must not consume cached `update-check.json` as authorization.

- [ ] **Step 4: Fetch and pin the candidate to a private ref**

Fetch:

```text
git fetch --quiet --force --no-tags origin refs/heads/main:refs/c2c/update-main
```

Then require:

```text
git rev-parse refs/c2c/update-main == verified manifest commit
git merge-base --is-ancestor HEAD <verified commit> exits 0
```

Never run `git pull` in the secure updater.

- [ ] **Step 5: Preserve local edits according to existing product behavior**

If `git status --porcelain` is non-empty:

```text
git stash push -u -m c2c-auto-update-<UTC timestamp>
```

Record the resulting stash ref in the JSON result. Do not auto-pop the stash; current behavior also moves local edits out of the update path and leaving the stash avoids conflict-driven corruption.

- [ ] **Step 6: Fast-forward to the exact verified commit**

Record `oldHead`, then:

```text
git merge --ff-only <verified commit>
```

Re-read `HEAD` and require exact equality with the signed commit before installing anything.

- [ ] **Step 7: Install/build from the signed frozen dependency graph**

Run in order:

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm build
```

Any non-zero exit begins rollback.

- [ ] **Step 8: Implement rollback**

On install/build failure:

```text
git reset --hard <oldHead>
corepack pnpm install --frozen-lockfile
corepack pnpm build
```

If rollback rebuild succeeds: return failure with `rolledBack: true` and do not restart bridge.

If rollback rebuild itself fails: return `stage: "rollback"`, `rolledBack: false`; never pretend the old version is healthy.

- [ ] **Step 9: Reinstall the Skill and restart using the newly built CLI**

On success:

1. copy `<repoRoot>/skill/SKILL.md` to `~/.codex/skills/codex-with-chatgpt/SKILL.md`;
2. patch only the line beginning `- The codex-with-chatgpt checkout lives at:` to the actual `repoRoot`;
3. spawn the newly built CLI for `sandbox-allow --json`;
4. spawn the newly built CLI for `restart -w <workspaceRoot> --json`;
5. refresh secure update-check state only after all post-update steps succeed.

- [ ] **Step 10: Add CLI command**

Add:

```text
c2c update -w <workspace> --json
```

The command calls only `performVerifiedUpdate()` and emits its structured result. It must not ask for confirmation.

- [ ] **Step 11: Replace raw update instructions in the Skill**

Daily workflow becomes:

```text
1. c2c update-check --json
2. if updateAvailable=true: c2c update -w <workspace> --json
3. continue original task
```

Remove instructions that directly run `git pull`, `git stash`, `pnpm install`, or manually restart as the update mechanism; those responsibilities are now inside the verified transaction.

- [ ] **Step 12: Run tests**

```bash
corepack pnpm vitest run tests/update-channel.test.ts tests/update-transaction.test.ts
```

- [ ] **Step 13: Commit**

```bash
git add src/update/transaction.ts src/cli/index.ts skill/SKILL.md tests/update-transaction.test.ts
git commit -m "feat: make automatic updates transactional and rollback-safe"
```

---

### Task 8: Create and publish the update trust root automatically

**Files:**
- Create: `scripts/generate-update-key.mjs`
- Create: `scripts/publish-update-channel.mjs`
- Create: `security/update-public-key.pem`
- Create: `.github/workflows/publish-update-channel.yml`
- Modify: `src/update/trust.ts`

**Interfaces:**

```text
node scripts/generate-update-key.mjs --public <path> --private <path>
node scripts/publish-update-channel.mjs --commit <sha> --repository <owner/repo> --branch main
```

Publisher reads private key only from `C2C_UPDATE_SIGNING_KEY_PEM`.

- [ ] **Step 1: Implement key generator**

Use Node `generateKeyPairSync("ed25519")`. Export public key as SPKI PEM and private key as PKCS8 PEM with filesystem mode `0600` for the private file.

The script must refuse to overwrite an existing private-key path unless an explicit `--force` flag is supplied.

- [ ] **Step 2: Generate the real project keypair once**

Run from repository root:

```bash
node scripts/generate-update-key.mjs \
  --public security/update-public-key.pem \
  --private /tmp/c2c-update-private.pem
```

Expected: public key file in repo; private key only under `/tmp` with mode 0600.

- [ ] **Step 3: Install the private key as the repository Actions secret**

Maintainer bootstrap command:

```bash
gh secret set C2C_UPDATE_SIGNING_KEY_PEM \
  --repo LeonAI-DO-YLCS/codex-with-chatgpt \
  < /tmp/c2c-update-private.pem
rm -f /tmp/c2c-update-private.pem
```

If `gh` is unavailable, set the same secret through GitHub repository settings; the secret name and value are identical. This is a maintainer/release operation, not end-user product configuration.

- [ ] **Step 4: Pin the public key in production verification**

`src/update/trust.ts` loads only `security/update-public-key.pem` from the currently installed checkout. Candidate update contents must never select or replace the verifier key before signature verification.

- [ ] **Step 5: Implement publisher canonical signing**

`publish-update-channel.mjs`:

1. validates commit is 40 lowercase hex and equals supplied/main CI SHA;
2. creates the canonical JSON bytes specified by the spec;
3. signs with `crypto.sign(null, bytes, privateKey)`;
4. writes Base64 signature plus LF;
5. creates a Git tree containing only `latest.json` and `latest.sig` using `git hash-object -w`, `git mktree`, `git commit-tree`;
6. pushes that commit to `refs/heads/c2c-update-channel` with force because this branch is a machine-generated pointer channel, not source history.

The script must never print the private key or environment value.

- [ ] **Step 6: Add publication workflow with a test gate**

`.github/workflows/publish-update-channel.yml` triggers on `push` to `main`, grants only `contents: write`, then runs:

```bash
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm typecheck
corepack pnpm test
corepack pnpm build
node scripts/publish-update-channel.mjs \
  --commit "$GITHUB_SHA" \
  --repository "$GITHUB_REPOSITORY" \
  --branch main
```

with `C2C_UPDATE_SIGNING_KEY_PEM` supplied from GitHub Actions secrets.

No signed channel update is published if install/typecheck/test/build fails.

- [ ] **Step 7: Test publisher locally with an ephemeral key/bare repo**

Do not use the production private key in tests. Extend `tests/update-channel.test.ts` to publish into a temp bare repo using an ephemeral key, then verify with the matching public key.

- [ ] **Step 8: Commit**

```bash
git add scripts/generate-update-key.mjs scripts/publish-update-channel.mjs security/update-public-key.pem .github/workflows/publish-update-channel.yml src/update/trust.ts tests/update-channel.test.ts
git commit -m "ci: publish cryptographically signed update channel"
```

**Gate:** Do not merge the implementation PR until `C2C_UPDATE_SIGNING_KEY_PEM` is installed and the workflow can publish/verify a channel entry for the merge candidate or a dedicated bootstrap commit.

---

### Task 9: Update security/architecture documentation without overstating guarantees

**Files:**
- Modify: `docs/security.md`
- Modify: `docs/architecture.md`
- Modify: `README.md`
- Modify: `README.zh-CN.md`

- [ ] **Step 1: Correct Cloudflare trust-boundary wording**

Document that Cloudflare Quick Tunnel is an accepted intermediary that transports MCP HTTPS traffic. Do not describe the repository as traveling directly from local machine to ChatGPT without an intermediary.

- [ ] **Step 2: Document exact read boundary**

State:

- read-only refers to **capability**, not local-only processing;
- path-denied sensitive files remain blocked;
- ordinary readable files are sent unchanged when requested;
- no content-level secret scanner/redactor is present by design.

- [ ] **Step 3: Document OAuth model accurately**

State that arbitrary HTTPS OAuth clients can dynamically register, pairing + PKCE authorize them, and the pairing page displays client identity/redirect origin. Do not claim provider allowlisting.

- [ ] **Step 4: Document execution-policy ownership**

Keep `UNTRUSTED_NOTE` and document that repository content is untrusted, but C2C does not authorize local commands; Codex/local-agent execution policy is the execution security boundary.

- [ ] **Step 5: Document signed automatic updates**

Include:

```text
main -> tests/build -> Ed25519-signed update-channel pointer -> local signature verification -> exact fast-forward -> frozen install/build -> restart
```

State the hardening release is the trust bootstrap; subsequent auto-updates are signature-verified.

- [ ] **Step 6: Commit**

```bash
git add docs/security.md docs/architecture.md README.md README.zh-CN.md
git commit -m "docs: document hardened trust boundaries"
```

---

### Task 10: Full regression and adversarial verification gate

**Files:**
- No new production files expected.
- Fix only defects exposed by the verification suite; do not broaden scope.

- [ ] **Step 1: Run static/package gates**

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm typecheck
corepack pnpm build
```

Expected: exit 0 for all commands.

- [ ] **Step 2: Run the complete test suite**

```bash
corepack pnpm test
```

Expected: all existing and new tests pass.

- [ ] **Step 3: Run explicit security negatives**

Confirm with tests or local scripted requests:

```text
malicious workspace HTML       -> rendered as text, CSP blocks scripts
malicious client_name HTML     -> rendered as text
invalid-only OAuth scope       -> invalid_scope, never all scopes
wrong OAuth resource           -> invalid_target
host-header spoof              -> cannot change issuer/resource URL
sensitive git status path      -> absent
sensitive rename old/new path  -> absent
public /health                 -> no workspaceId
unauthenticated /admin/info    -> 404
proxied /admin/info            -> 404
tampered update manifest       -> rejected before checkout mutation
wrong signing key              -> rejected
remote main/channel mismatch   -> no update; retry later
non-fast-forward signed target -> rejected
candidate build failure        -> previous HEAD restored, no bridge restart
```

- [ ] **Step 4: Verify no capability regression**

Run an end-to-end bridge smoke test with a real configured cloud client:

1. `c2c setup -w <test-workspace> --json`;
2. start Cloudflare tunnel;
3. complete OAuth pairing;
4. call `workspace_info`, `list_directory`, `read_file`, `search_workspace`, `git_status`, `git_diff`, `test_status`, `execution_summary`;
5. execute one normal Codex iteration under existing local agent policy;
6. cloud reviewer reads resulting diff/status and reaches review/DONE.

Expected: every existing read-only MCP capability remains available; no new permission/config prompt is introduced.

- [ ] **Step 5: Verify signed zero-touch update end-to-end**

Using a controlled test release after the trust bootstrap:

1. publish `main` through the workflow;
2. confirm `c2c-update-channel` points to the exact tested main SHA;
3. from the previous installed version run `c2c update-check --force --json` and require `updateAvailable: true`;
4. run `c2c update -w <test-workspace> --json` with no confirmation;
5. require exact new SHA, frozen install/build success, skill reinstall, bridge restart, and successful MCP call after restart.

- [ ] **Step 6: Self-review against the normative spec**

Check each SH-01 through SH-08 and every global constraint. Search the implementation diff for accidental additions of:

```text
provider allowlist
content secret scanner/redactor
new MCP write/exec capability
transmission audit log
update confirmation prompt
execution-plan rejection/filter layer
```

Any such addition is a spec violation unless separately approved.

- [ ] **Step 7: Commit any verification-only fixes**

If verification required code corrections, commit each focused correction separately. If no corrections are needed, do not create an empty commit.

---

## Required final implementation evidence

The implementation PR is not ready for merge until its description contains:

- baseline commit and final head SHA;
- output summary for `pnpm typecheck`, `pnpm build`, and full `pnpm test`;
- count of tests before/after;
- successful hostile-workspace-name XSS regression result;
- successful OAuth invalid-scope and invalid-resource regression result;
- successful sensitive `git_status` regression result;
- proof public `/health` omits `workspaceId`;
- signed update-channel verification success;
- tampered-signature rejection success;
- rollback test result;
- signed zero-touch update smoke-test result;
- explicit statement that Cloudflare, arbitrary HTTPS OAuth clients, full read-only workspace capability, local-agent execution authority, no content redaction, no transmission audit log, shared provider state, and zero-config UX remain unchanged.

## Implementation order rationale

Tasks 1–4 patch remotely reachable data/control surfaces first and are independently reviewable. Task 5 freezes dependency resolution before the updater begins depending on it. Tasks 6–8 build the signed update trust chain from verifier to transaction to publisher. Task 9 updates documentation only after behavior is final. Task 10 is the mandatory cross-cutting security and no-regression gate.

## Trust bootstrap note

There is no way for an already-installed unsigned auto-updater to retroactively authenticate the first hardening update. Therefore the version implementing this plan is the one-time trusted bootstrap. Install/merge that version through an already trusted channel. From that point forward, the currently installed pinned Ed25519 public key authenticates every automatic update before local checkout mutation.
