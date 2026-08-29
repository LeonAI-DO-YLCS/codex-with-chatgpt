# C2C Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Patch the confirmed C2C security findings without removing capabilities, adding provider restrictions, adding content redaction, adding an execution sandbox/firewall, or changing the zero-touch end-user experience.

**Architecture:** Preserve the current read-only MCP + OAuth + Cloudflare tunnel + local Codex execution split. Harden only the exposed trust boundaries: OAuth rendering and validation, Git metadata filtering, public bridge metadata, deterministic dependencies, and automatic update integrity. Automatic client updates remain zero-touch, but update authenticity is anchored in a signing key that repository-controlled code cannot access.

**Tech Stack:** Node.js >=20, TypeScript 5.9, Express 5, MCP TypeScript SDK 1.30.0, Commander 14, Vitest 3, pnpm 11.24, Node built-in `crypto` Ed25519, Git.

**Spec:** `docs/security-hardening-spec.md`

## Global Constraints

- Cloudflare remains supported and enabled.
- All approved cloud providers receive the same bridge capabilities.
- Workspace access remains allow-by-default except existing `IgnoreRules` / `.c2cignore` denials.
- Do not add content-level secret scanning or redaction.
- Keep arbitrary HTTPS OAuth clients plus localhost HTTP development clients.
- Keep all current read-only MCP tools.
- Do not add C2C plan filtering, command sandboxing, or execution allowlists.
- End-user updates remain automatic; no confirmation prompt.
- Do not add transmission audit logging.
- Provider sessions continue sharing project/workspace execution state.
- Do not add user-facing security profiles or mandatory configuration.
- Do not add write/delete/shell/commit/install MCP tools.
- Use TDD for each behavior change.
- If this plan and `docs/security-hardening-spec.md` ever differ, the spec wins.

---

## File Map

### Create

- `src/security/html.ts` — HTML escaping helper.
- `src/update/trust.ts` — update-channel constants and pinned public-key loading.
- `src/update/channel.ts` — manifest canonicalization, Ed25519 verification, signed-channel checks.
- `src/update/transaction.ts` — exact-target fast-forward, install/build, rollback, post-update restart.
- `scripts/generate-update-key.mjs` — maintainer-only Ed25519 key generation.
- `scripts/publish-update-channel.mjs` — maintainer-only detached signing + channel publication.
- `security/update-public-key.pem` — committed public trust root.
- `.github/workflows/ci.yml` — non-signing install/typecheck/test/build gate; it never receives the release-signing private key.
- `tests/update-channel.test.ts` — crypto/channel tests.
- `tests/update-transaction.test.ts` — update transaction tests.

### Modify

- `src/auth/oauth.ts`
- `src/auth/store.ts`
- `src/bridge/server.ts`
- `src/bridge/runtime.ts`
- `src/workspace/git.ts`
- `src/mcp/server.ts`
- `src/cli/index.ts`
- `skill/SKILL.md`
- `package.json`
- `pnpm-lock.yaml` only if necessary after exact-version pin
- `README.md`
- `README.zh-CN.md`
- `docs/security.md`
- `docs/architecture.md`
- `tests/oauth.test.ts`
- `tests/git.test.ts`
- `tests/mcp-integration.test.ts`
- `tests/port.test.ts`

---

### Task 1: Harden OAuth pairing-page rendering

**Files:**
- Create: `src/security/html.ts`
- Modify: `src/auth/oauth.ts`
- Test: `tests/oauth.test.ts`

**Interfaces:**

```ts
export function escapeHtml(value: string): string;
```

Inside `oauth.ts` add:

```ts
function setAuthorizationPageHeaders(res: Response): void;
```

`pairingPage()` must accept `clientName` and `redirectOrigin` in addition to current fields.

- [ ] **Step 1: Add failing XSS regression tests**

Create a bridge workspace containing:

```ts
write(root, ".c2c.json", JSON.stringify({
  name: `<img src=x onerror="globalThis.pwned=1"> & \"project\"`,
}));
```

Register a client using:

```ts
{
  client_name: `<script>globalThis.pwned=1</script> Reviewer`,
  redirect_uris: ["https://agent.example/callback"]
}
```

Assert authorization HTML contains escaped text and never contains executable `<script>` or `<img ... onerror>` markup.

- [ ] **Step 2: Add failing header assertions**

Require exact headers:

```text
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'
Cache-Control: no-store
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
```

- [ ] **Step 3: Add client-identity assertions**

The page must not say `ChatGPT is requesting access`. It must render the registered client name and `new URL(redirectUri).origin`, with provider-neutral wording.

- [ ] **Step 4: Run the focused test and confirm failure**

```bash
corepack pnpm vitest run tests/oauth.test.ts
```

- [ ] **Step 5: Implement HTML escaping**

Create:

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

Escape every dynamic value inserted into the page: product name, client name, redirect origin, workspace name, request ID, error text, and scope text.

- [ ] **Step 6: Apply response headers to both success and error pairing pages**

Call `setAuthorizationPageHeaders()` before every `.type("html").send(pairingPage(...))` path.

- [ ] **Step 7: Verify normal OAuth flow remains intact**

```bash
corepack pnpm vitest run tests/oauth.test.ts
```

Expected: all original OAuth tests and new XSS/header tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/security/html.ts src/auth/oauth.ts tests/oauth.test.ts
git commit -m "fix: harden OAuth pairing page rendering"
```

---

### Task 2: Fix OAuth scope escalation and target/base-URL validation

**Files:**
- Modify: `src/auth/store.ts`
- Modify: `src/auth/oauth.ts`
- Modify: `src/bridge/server.ts`
- Test: `tests/oauth.test.ts`

**Interfaces:**

Replace `filterScopes()` with:

```ts
export type ScopeResolution =
  | { ok: true; scopes: Scope[] }
  | { ok: false; error: "invalid_scope" };

export function resolveScopes(requested?: string): ScopeResolution;
```

- [ ] **Step 1: Add scope tests**

Required behavior:

```text
scope omitted                 -> all current scopes
scope="workspace.read"        -> workspace.read only
scope="workspace.read nope"   -> workspace.read only
scope="totally.invalid"       -> OAuth invalid_scope; no pairing page
```

Preserve `state` on the invalid-scope redirect.

- [ ] **Step 2: Add `resource` tests**

Required behavior:

```text
resource omitted                       -> accepted
resource=<base>/mcp                    -> accepted
resource=<base>/mcp/                   -> accepted
resource=https://attacker.example/mcp  -> invalid_target
resource=not-a-url                     -> invalid_target
```

- [ ] **Step 3: Add Host/forwarded-header regression test**

Before a tunnel exists, request discovery metadata with hostile `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto`. Assert issuer/resource still use the bridge's known `host` + actual `port`.

- [ ] **Step 4: Run tests and confirm failure**

```bash
corepack pnpm vitest run tests/oauth.test.ts
```

- [ ] **Step 5: Implement `resolveScopes` exactly**

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

- [ ] **Step 6: Validate scope and resource before storing pending authorization state**

In `GET /oauth/authorize`:

1. resolve scopes;
2. on invalid-only scopes, use existing redirect helper with `invalid_scope`;
3. compute canonical MCP target from `deps.getBaseUrl(req) + "/mcp"`;
4. if `resource` exists, parse and normalize only an optional trailing slash;
5. reject malformed/mismatched target with `invalid_target`;
6. only then create `PendingAuthRequest`.

- [ ] **Step 7: Remove request headers from local issuer authority**

In `src/bridge/server.ts`:

```ts
const getBaseUrl = (_req: Request): string => {
  if (publicBaseUrl) return publicBaseUrl;
  return `http://${host}:${port}`;
};
```

Replace global proxy trust with loopback-only trust:

```ts
app.set("trust proxy", (ip: string) =>
  ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1"
);
```

- [ ] **Step 8: Run OAuth tests**

```bash
corepack pnpm vitest run tests/oauth.test.ts
```

- [ ] **Step 9: Commit**

```bash
git add src/auth/store.ts src/auth/oauth.ts src/bridge/server.ts tests/oauth.test.ts
git commit -m "fix: tighten OAuth scope and target validation"
```

---

### Task 3: Apply `IgnoreRules` to `git_status`

**Files:**
- Modify: `src/workspace/git.ts`
- Modify: `src/mcp/server.ts`
- Test: `tests/git.test.ts`
- Test: `tests/mcp-integration.test.ts`

**Interface change:**

```ts
gitStatus(root: string)
```

becomes:

```ts
gitStatus(target: GitTarget)
```

`GitStatusResult` shape remains unchanged.

- [ ] **Step 1: Add unit tests for sensitive status names**

Cover staged, unstaged, untracked, conflicted, custom `.c2cignore`, and rename/copy cases for:

```text
.env
.npmrc
credentials.json
private/.ssh/config
custom-secret.txt
```

Safe files must remain visible.

- [ ] **Step 2: Add rename provenance cases**

At minimum:

```text
.npmrc -> visible.txt
visible.txt -> .env.production
```

If either old or new path is sensitive, omit the entire record.

- [ ] **Step 3: Add MCP integration regression**

Call `git_status` with a valid `git.read` token and assert denied paths are absent from the tool JSON.

- [ ] **Step 4: Run and confirm failure**

```bash
corepack pnpm vitest run tests/git.test.ts tests/mcp-integration.test.ts
```

- [ ] **Step 5: Reuse the same target/ignore construction as `gitDiff`**

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

Use `git status --porcelain=v2 --branch -z -- .` and parse NUL-delimited records so filenames are not security-decoded through quoted text.

- [ ] **Step 6: Filter every path-bearing collection**

Apply `ignoreRules.isSensitive()` before adding paths to:

- `staged`
- `unstaged`
- `untracked`
- `conflicted`

For porcelain-v2 type `2` rename/copy records, consume both new and original path fields and require both to be non-sensitive.

Do not alter branch/upstream/ahead/behind metadata.

- [ ] **Step 7: Change MCP call site**

```ts
return ok(gitStatus(workspace));
```

- [ ] **Step 8: Run focused tests**

```bash
corepack pnpm vitest run tests/git.test.ts tests/mcp-integration.test.ts
```

- [ ] **Step 9: Commit**

```bash
git add src/workspace/git.ts src/mcp/server.ts tests/git.test.ts tests/mcp-integration.test.ts
git commit -m "fix: hide denied paths from git status"
```

---

### Task 4: Remove workspace identity from public `/health`

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

- [ ] **Step 1: Add failing privacy test**

```ts
const health = await probeBridge(bridge.port);
expect(health?.service).toBe("codex-with-chatgpt");
expect("workspaceId" in (health ?? {})).toBe(false);
```

- [ ] **Step 2: Add authenticated local identity test**

Start a bridge with persisted runtime state, then assert `findLiveBridge(workspace.id)` still returns the correct state by using the stored admin token.

Also assert `/admin/info` without token and with proxy headers returns 404.

- [ ] **Step 3: Run and confirm failure**

```bash
corepack pnpm vitest run tests/port.test.ts
```

- [ ] **Step 4: Minimize public health payload**

Return only:

```ts
{ service: SERVICE_NAME, version: VERSION, status: "ok" }
```

Do not change `Workspace.id` generation.

- [ ] **Step 5: Move workspace identity validation to authenticated loopback admin probe**

`probeRuntimeState(state)` calls:

```text
GET http://127.0.0.1:<state.port>/admin/info
Authorization: Bearer <state.adminToken>
```

`findLiveBridge(workspaceId)` reads the workspace's 0600 runtime file, calls `probeRuntimeState`, and returns the state only if `workspaceId` matches.

- [ ] **Step 6: Run tests**

```bash
corepack pnpm vitest run tests/port.test.ts
```

- [ ] **Step 7: Commit**

```bash
git add src/bridge/server.ts src/bridge/runtime.ts tests/port.test.ts
git commit -m "fix: remove workspace identity from public health"
```

---

### Task 5: Make dependency resolution deterministic

**Files:**
- Modify: `package.json`
- Modify if required: `pnpm-lock.yaml`
- Modify: `skill/SKILL.md`
- Modify: `README.md`
- Modify: `README.zh-CN.md`

- [ ] **Step 1: Pin current MCP SDK without upgrading it**

Change:

```json
"@modelcontextprotocol/sdk": "1.30.0"
```

Do not change unrelated dependency versions.

- [ ] **Step 2: Verify lock consistency**

```bash
corepack pnpm install --frozen-lockfile
```

If pnpm requires importer metadata refresh because the manifest changed from `latest` to `1.30.0`, run:

```bash
corepack pnpm install --lockfile-only
corepack pnpm install --frozen-lockfile
```

Review the lockfile and reject any unrelated dependency upgrade.

- [ ] **Step 3: Change automated install instructions**

All automated first-time/update install paths must use:

```bash
corepack pnpm install --frozen-lockfile
```

- [ ] **Step 4: Verify**

```bash
corepack pnpm typecheck
corepack pnpm build
corepack pnpm test
```

- [ ] **Step 5: Commit**

```bash
git add package.json pnpm-lock.yaml skill/SKILL.md README.md README.zh-CN.md
git commit -m "chore: make dependency installs deterministic"
```

---

### Task 6: Build the signed update-channel verifier

**Files:**
- Create: `src/update/trust.ts`
- Create: `src/update/channel.ts`
- Create: `tests/update-channel.test.ts`

**Interfaces:**

```ts
export interface UpdateManifest {
  schema: 1;
  repository: "LeonAI-DO-YLCS/codex-with-chatgpt";
  branch: "main";
  commit: string;
  publishedAt: string;
}

export type UpdateCheckResult =
  | {
      ok: true;
      updateAvailable: boolean;
      localCommit: string;
      remoteCommit: string;
      manifest: UpdateManifest;
    }
  | {
      ok: false;
      reason:
        | "offline"
        | "unsigned"
        | "invalid_signature"
        | "invalid_manifest"
        | "channel_not_ready"
        | "git_error";
      message: string;
    };

export function canonicalManifestBytes(manifest: UpdateManifest): Buffer;
export function verifyManifest(
  manifestText: string,
  signatureText: string,
  publicKeyPem: string
): UpdateManifest;
export function checkVerifiedUpdate(opts: {
  repoRoot: string;
  remote?: string;
  publicKeyPem?: string;
}): UpdateCheckResult;
```

Constants:

```ts
export const UPDATE_REPOSITORY = "LeonAI-DO-YLCS/codex-with-chatgpt";
export const UPDATE_BRANCH = "main";
export const UPDATE_CHANNEL_REMOTE_REF = "refs/heads/c2c-update-channel";
export const UPDATE_CHANNEL_LOCAL_REF = "refs/c2c/update-channel";
```

- [ ] **Step 1: Add pure crypto tests using ephemeral Ed25519 keys**

Positive: valid canonical manifest + matching signature.

Negative:

- one-byte manifest change;
- malformed Base64 signature;
- signature from another key;
- wrong schema;
- wrong repository;
- wrong branch;
- malformed/non-40-lowercase-hex commit;
- invalid/non-UTC `publishedAt`;
- non-canonical JSON representation.

- [ ] **Step 2: Add local-Git channel integration test**

Create a temp working repo + temp bare `origin` with `main` at A then B and `c2c-update-channel` containing a valid detached signature for B. Assert `updateAvailable: true`.

Tamper with `latest.json` without signing and assert failure.

No network is allowed in this test.

- [ ] **Step 3: Run and confirm failure**

```bash
corepack pnpm vitest run tests/update-channel.test.ts
```

- [ ] **Step 4: Implement exact canonical bytes**

```ts
export function canonicalManifestBytes(manifest: UpdateManifest): Buffer {
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
}
```

Reject a received JSON file whose raw bytes differ from canonical serialization of the parsed object.

- [ ] **Step 5: Implement Ed25519 verification with Node built-ins**

```ts
import { verify } from "node:crypto";

const ok = verify(
  null,
  canonicalBytes,
  publicKeyPem,
  Buffer.from(signatureText.trim(), "base64")
);
```

No third-party crypto package.

- [ ] **Step 6: Implement channel fetch/verification**

Use bounded `git` subprocesses with `GIT_TERMINAL_PROMPT=0`:

```text
git rev-parse HEAD
git ls-remote origin refs/heads/main refs/heads/c2c-update-channel
git fetch --quiet --force --no-tags origin refs/heads/c2c-update-channel:refs/c2c/update-channel
git show refs/c2c/update-channel:latest.json
git show refs/c2c/update-channel:latest.sig
```

Required order:

1. both remote refs exist;
2. signature verifies under the currently installed key;
3. manifest schema/repository/branch/SHA/time validate;
4. signed commit equals remote `main` SHA;
5. only then report an update.

If `main` moved before the signed channel was published, return `channel_not_ready`; do not cache the day as successfully checked.

- [ ] **Step 7: Keep pinned-key loading lazy**

`src/update/trust.ts` must expose a function that reads `security/update-public-key.pem` only when production code does not inject a key. This lets tests inject ephemeral public keys and avoids reading candidate-update content before verification.

- [ ] **Step 8: Run tests and commit**

```bash
corepack pnpm vitest run tests/update-channel.test.ts
git add src/update/trust.ts src/update/channel.ts tests/update-channel.test.ts
git commit -m "feat: verify automatic updates with signed channel"
```

---

### Task 7: Replace raw update checking/installing with a verified transaction

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
  | {
      ok: false;
      stage:
        | "verify"
        | "fetch"
        | "fast_forward"
        | "install"
        | "build"
        | "rollback"
        | "post_update";
      message: string;
      rolledBack: boolean;
    };

export function performVerifiedUpdate(
  opts: UpdateTransactionOptions
): UpdateTransactionResult;
```

- [ ] **Step 1: Add transaction tests**

Required cases:

1. signed A -> B fast-forward succeeds;
2. unsigned/tampered channel changes nothing;
3. channel manifest SHA != remote `main` changes nothing;
4. non-fast-forward target is rejected;
5. dirty tracked + untracked checkout is stashed before mutation;
6. install failure restores A;
7. build failure restores A;
8. post-update restart hook is never called after verification/install/build failure;
9. moving `main` after verification cannot change the exact target actually installed.

Inject command execution/post-update hooks in tests so no real package install or process restart occurs.

- [ ] **Step 2: Run and confirm failure**

```bash
corepack pnpm vitest run tests/update-transaction.test.ts
```

- [ ] **Step 3: Refactor `c2c update-check` to use the signed channel**

Remove direct trust in `git ls-remote origin HEAD` as the update decision.

`update-check` must call `checkVerifiedUpdate()` and:

- cache a daily result only when `ok: true`;
- not cache `offline`, `invalid_signature`, `invalid_manifest`, `unsigned`, `channel_not_ready`, or `git_error` as a successful daily check;
- return machine-readable failure/status without mutating the checkout.

- [ ] **Step 4: Re-verify at update time**

`performVerifiedUpdate()` always calls `checkVerifiedUpdate()` again. Cached update-check output is never authorization to modify files.

- [ ] **Step 5: Fetch exact main target into private ref**

```text
git fetch --quiet --force --no-tags origin refs/heads/main:refs/c2c/update-main
```

Require:

```text
git rev-parse refs/c2c/update-main == signed manifest commit
git merge-base --is-ancestor HEAD <signed commit> exits 0
```

Never run `git pull` in the secure updater.

- [ ] **Step 6: Preserve current local-edit behavior**

If `git status --porcelain` is non-empty:

```text
git stash push -u -m c2c-auto-update-<UTC timestamp>
```

Record the stash ref in JSON. Do not auto-pop it.

- [ ] **Step 7: Update to exact signed SHA**

Record `oldHead`, then:

```text
git merge --ff-only <signed commit>
```

Re-read `HEAD` and require exact equality with signed commit.

- [ ] **Step 8: Install/build deterministically**

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm build
```

- [ ] **Step 9: Roll back on install/build failure**

```text
git reset --hard <oldHead>
corepack pnpm install --frozen-lockfile
corepack pnpm build
```

If rollback rebuild succeeds, report `rolledBack: true` and do not restart the bridge. If rollback rebuild fails, return `stage: "rollback"`, `rolledBack: false`.

- [ ] **Step 10: Reinstall skill and restart only after successful build**

1. copy repo `skill/SKILL.md` to `~/.codex/skills/codex-with-chatgpt/SKILL.md`;
2. patch only the `checkout lives at:` line to actual repo root;
3. invoke newly built CLI `sandbox-allow --json`;
4. invoke newly built CLI `restart -w <workspaceRoot> --json`;
5. refresh update-check state after post-update success.

- [ ] **Step 11: Add CLI command**

```text
c2c update -w <workspace> --json
```

No confirmation prompt.

- [ ] **Step 12: Replace Skill raw update workflow**

Daily flow becomes:

```text
c2c update-check --json
if updateAvailable=true -> c2c update -w <workspace> --json
continue original task
```

Remove raw `git pull`, raw update `pnpm install`, and manual restart steps from the Skill's update workflow.

- [ ] **Step 13: Verify and commit**

```bash
corepack pnpm vitest run tests/update-channel.test.ts tests/update-transaction.test.ts
git add src/update/transaction.ts src/cli/index.ts skill/SKILL.md tests/update-transaction.test.ts
git commit -m "feat: make automatic updates verified and rollback-safe"
```

---

### Task 8: Create the independent update-signing trust root

**Files:**
- Create: `scripts/generate-update-key.mjs`
- Create: `scripts/publish-update-channel.mjs`
- Create: `security/update-public-key.pem`
- Create: `.github/workflows/ci.yml`
- Modify: `src/update/trust.ts`
- Test: `tests/update-channel.test.ts`

**Critical rule:** The private signing key MUST NOT be stored in Git, GitHub Actions secrets, repository environments, or any CI/workflow whose code can be changed by this repository. Repository CI may test commits, but it never receives the signing key.

**Interfaces:**

```text
node scripts/generate-update-key.mjs --public <path> --private <path>
node scripts/publish-update-channel.mjs \
  --commit <sha> \
  --repository LeonAI-DO-YLCS/codex-with-chatgpt \
  --branch main \
  --private-key <path>
```

- [ ] **Step 1: Implement maintainer key generator**

Use `generateKeyPairSync("ed25519")`.

- public: SPKI PEM;
- private: PKCS8 PEM;
- private file mode: `0600`;
- refuse to overwrite private-key path unless `--force` is explicitly supplied.

- [ ] **Step 2: Generate the real keypair in a trusted maintainer environment**

Example command:

```bash
node scripts/generate-update-key.mjs \
  --public security/update-public-key.pem \
  --private "$HOME/.config/c2c-release/update-private.pem"
```

The private path must be outside the repository and backed up securely. Do not place it under the checkout.

- [ ] **Step 3: Pin public key in current-version verifier**

`src/update/trust.ts` reads only the committed `security/update-public-key.pem` from the currently installed version. A candidate update can rotate the public key only if that candidate itself is authenticated by the old key.

- [ ] **Step 4: Implement maintainer publisher**

`publish-update-channel.mjs` must:

1. verify the requested commit is 40 lowercase hex;
2. verify `git cat-file -e <sha>^{commit}` succeeds;
3. require the commit to be reachable from current `origin/main` before signing;
4. generate canonical `latest.json` exactly per spec;
5. sign exact bytes with `crypto.sign(null, bytes, privateKey)`;
6. write Base64 signature + LF;
7. create a Git tree containing only `latest.json` + `latest.sig` via `git hash-object -w`, `git mktree`, `git commit-tree`;
8. set explicit commit identity for the generated channel commit:

```text
GIT_AUTHOR_NAME=C2C Update Signer
GIT_AUTHOR_EMAIL=c2c-update@local.invalid
GIT_COMMITTER_NAME=C2C Update Signer
GIT_COMMITTER_EMAIL=c2c-update@local.invalid
```

9. push that generated commit to `refs/heads/c2c-update-channel` with force;
10. never print private-key bytes.

- [ ] **Step 5: Add publisher tests with ephemeral key**

Use a temporary bare repo and ephemeral keypair. Publish a signed channel entry, then verify it using `checkVerifiedUpdate()`.

- [ ] **Step 6: Add repository CI as a non-signing gate**

Create `.github/workflows/ci.yml` triggered on pull requests and pushes to `main`, with only the permissions needed to read repository contents. It runs:

```bash
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm typecheck
corepack pnpm test
corepack pnpm build
```

The workflow MUST NOT reference a release-signing secret or receive the private signing key.

- [ ] **Step 7: Define the maintainer release procedure**

After the exact `main` SHA passes CI, from the trusted maintainer machine:

```bash
git fetch origin main
TARGET="$(git rev-parse origin/main)"
node scripts/publish-update-channel.mjs \
  --commit "$TARGET" \
  --repository LeonAI-DO-YLCS/codex-with-chatgpt \
  --branch main \
  --private-key "$HOME/.config/c2c-release/update-private.pem"
```

This release-signing step is maintainer-side. End users still receive and install the signed update automatically without confirmation.

If fully unattended release signing is later required, replace the trusted maintainer machine with an independently controlled signing service/KMS whose policy cannot be changed by this source repository. Do not move the private key into repository Actions to achieve convenience.

- [ ] **Step 8: Commit public artifacts/tooling only**

```bash
git add scripts/generate-update-key.mjs scripts/publish-update-channel.mjs security/update-public-key.pem src/update/trust.ts tests/update-channel.test.ts .github/workflows/ci.yml
git commit -m "feat: establish independent update signing trust root"
```

Never add the private key.

---

### Task 9: Update security and architecture documentation

**Files:**
- Modify: `docs/security.md`
- Modify: `docs/architecture.md`
- Modify: `README.md`
- Modify: `README.zh-CN.md`

- [ ] **Step 1: Correct Cloudflare trust-boundary wording**

Document Cloudflare Quick Tunnel as an accepted intermediary for MCP HTTPS traffic.

- [ ] **Step 2: Document exact read boundary**

State clearly:

- `read-only` describes bridge capability, not local-only data processing;
- path-denied files remain blocked;
- readable ordinary files are returned unchanged;
- there is intentionally no content-level secret scanner/redactor.

- [ ] **Step 3: Document arbitrary OAuth client support accurately**

State that arbitrary HTTPS clients can dynamically register and are authorized through pairing + PKCE; the pairing page shows client identity and redirect origin.

- [ ] **Step 4: Document execution-policy ownership**

Keep `UNTRUSTED_NOTE`. State that C2C does not authorize local shell execution; Codex/local-agent policy is authoritative.

- [ ] **Step 5: Document signed automatic update flow**

```text
main passes CI
    -> trusted maintainer signs exact SHA outside repository-controlled CI
    -> c2c-update-channel carries latest.json + latest.sig
    -> installed client verifies with current pinned key
    -> exact fast-forward
    -> frozen install/build
    -> restart
```

- [ ] **Step 6: Document trust bootstrap**

The hardening release is the one-time trusted bootstrap. Signature-enforced automatic updates apply after it is installed.

- [ ] **Step 7: Commit**

```bash
git add docs/security.md docs/architecture.md README.md README.zh-CN.md
git commit -m "docs: document hardened trust boundaries"
```

---

### Task 10: Full regression and adversarial verification gate

**Files:** No planned new production files.

- [ ] **Step 1: Run package/static gates**

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm typecheck
corepack pnpm build
```

Expected: exit 0.

- [ ] **Step 2: Run complete tests**

```bash
corepack pnpm test
```

Expected: all tests pass.

- [ ] **Step 3: Run explicit security negatives**

Verify each result:

```text
malicious workspace HTML       -> rendered as text; CSP blocks scripts
malicious client_name HTML     -> rendered as text
invalid-only OAuth scope       -> invalid_scope; never all scopes
wrong OAuth resource           -> invalid_target
Host-header spoof              -> cannot change issuer/resource URL
sensitive git status path      -> absent
sensitive rename old/new path  -> absent
public /health                 -> no workspaceId
unauthenticated /admin/info    -> 404
proxied /admin/info            -> 404
tampered update manifest       -> rejected before checkout mutation
wrong signing key              -> rejected
remote main/channel mismatch   -> no update; retry later
non-fast-forward signed target -> rejected
candidate build failure        -> previous HEAD restored; no bridge restart
```

- [ ] **Step 4: Verify no feature regression end-to-end**

Using a real test workspace and configured cloud client:

1. `c2c setup -w <test-workspace> --json`;
2. start Cloudflare tunnel;
3. pair via OAuth;
4. successfully call all existing tools: `workspace_info`, `list_directory`, `read_file`, `search_workspace`, `git_status`, `git_diff`, `test_status`, `execution_summary`;
5. run one normal Codex iteration under existing local policy;
6. cloud reviewer reads diff/status and reaches review/DONE.

No new permission/config prompt may appear.

- [ ] **Step 5: Verify signed zero-touch end-user update**

1. install previous trusted hardening-capable version;
2. publish a newer exact tested `main` SHA through `publish-update-channel.mjs` using the independent key;
3. run `c2c update-check --force --json` and require `updateAvailable: true`;
4. run `c2c update -w <test-workspace> --json` without confirmation;
5. require exact signed SHA, frozen install/build success, skill reinstall, bridge restart, and successful MCP request after restart.

- [ ] **Step 6: Verify private signing key isolation**

Search the repository and workflow configuration for the private key or a signing-key secret reference. There must be none.

The only committed trust material is `security/update-public-key.pem`.

- [ ] **Step 7: Self-review against spec**

Search the diff for accidental additions of:

```text
provider allowlist
content secret scanner/redactor
new MCP write/exec tool
transmission audit log
end-user update confirmation
C2C execution-plan rejection/filter layer
repository-controlled release signing secret
```

Any such addition is a spec violation.

- [ ] **Step 8: Commit only real corrections**

If verification exposes defects, fix and commit them separately. Do not create an empty verification commit.

---

## Required Implementation PR Evidence

The implementation PR is not merge-ready until its description contains:

- baseline commit and final head SHA;
- `pnpm typecheck`, `pnpm build`, and full `pnpm test` results;
- test count before/after;
- XSS hostile-workspace regression result;
- OAuth invalid-scope result;
- OAuth invalid-resource result;
- sensitive `git_status` result;
- proof public `/health` omits `workspaceId`;
- valid signed-channel verification result;
- tampered-signature rejection result;
- non-fast-forward rejection result;
- rollback test result;
- signed zero-touch update smoke-test result;
- proof the private signing key is outside Git and repository-controlled CI;
- explicit statement that Cloudflare, arbitrary HTTPS OAuth clients, full read-only workspace capability, local-agent execution authority, no content redaction, no transmission audit log, shared provider state, and zero-config UX remain unchanged.

## Implementation Order Rationale

Tasks 1–4 patch reachable browser/OAuth/data surfaces first. Task 5 freezes dependency resolution before it becomes part of the secure updater. Tasks 6–8 build the update trust chain in the correct order: verifier, transactional installer, then independent trust root/publisher. Task 9 documents the final behavior. Task 10 is the mandatory no-regression/security gate.

## Trust Bootstrap

An already-installed unsigned updater cannot retroactively authenticate the first hardening update. Therefore the version implementing this plan is the one-time trusted bootstrap and must be installed through an already trusted channel. After that, the currently installed Ed25519 public key authenticates every automatic client update before local checkout mutation.
