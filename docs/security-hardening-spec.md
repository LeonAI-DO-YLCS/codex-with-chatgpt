# Security Hardening Specification — No Feature Loss

**Status:** Approved design constraints for implementation

**Baseline:** `main` at `b1481c0b80936308d4b380a65466e8bd534abc5e`

**Objective:** Harden Codex with ChatGPT against data-exfiltration, OAuth, browser-rendering, metadata-leakage, update-chain, and dependency-integrity risks without changing the product's operating model or reducing agent capability.

## 1. Product invariants

These are locked. An implementation that violates any item is incorrect even if it is more restrictive or conventionally "safer."

1. **Cloudflare remains supported and enabled.** The bridge may continue to use Cloudflare Quick Tunnel. Cloudflare is an accepted transport processor/trust boundary.
2. **Approved cloud providers receive the same bridge capabilities.** Do not add provider-specific MCP capability profiles.
3. **Workspace access remains allow-by-default.** Cloud agents may inspect the whole workspace except paths already denied by `IgnoreRules` / `.c2cignore`.
4. **Do not add content-level secret scanning or redaction.** Existing path-level sensitive-file protections remain, but ordinary readable files are returned unchanged.
5. **Dynamic OAuth client registration remains open to arbitrary HTTPS clients** and `http://localhost` / `http://127.0.0.1` for development. Do not add an OpenAI/provider allowlist.
6. **All existing read-only MCP tools remain available.** The cloud agent decides which read-only tools to request for the task. Do not remove or downgrade tools.
7. **C2C does not become an execution firewall.** Codex/local-agent execution policy remains authoritative. Do not add plan rejection, command sandboxing, or C2C execution allowlists.
8. **Updates remain fully automatic and zero-touch for end users.** Security hardening may add cryptographic verification, rollback, and deterministic installation, but must not add an end-user confirmation step.
9. **Do not add transmission audit logging.** No new logs of file contents, tool payloads, paths sent to providers, or provider-by-provider transmission history.
10. **Provider sessions continue sharing workspace/project execution state** as they do today; do not introduce provider isolation layers.
11. **Zero-config UX remains the default.** Do not add security profiles, provider permission setup, or mandatory user-facing security configuration.
12. **Cloud providers remain read-only with respect to the bridge.** No write/delete/shell/commit/install MCP tools are added.

## 2. Accepted residual risks / non-goals

The following are deliberate product decisions and must not be reopened by an implementation agent unless the owner changes this specification:

- Workspace data requested through MCP can transit Cloudflare before reaching the configured cloud provider.
- Readable ordinary files may contain credentials or secrets; C2C does not inspect/redact their contents.
- Any HTTPS OAuth client may register. Security comes from pairing + PKCE + token controls, not provider allowlisting.
- Repository content may influence a cloud model's planning. C2C's tool descriptions continue to mark repository content as untrusted, but local execution safety remains the Codex/local-agent responsibility.
- No new transmission audit trail is created.
- The end-user update process remains automatic. Release signing is a maintainer trust operation and is not exposed to end users.

## 3. Findings that MUST be fixed

### SH-01 — Stored/reflected HTML injection in OAuth pairing UI

**Current location:** `src/auth/oauth.ts`, `pairingPage()`.

`workspaceName`, error text, and rendered scope labels are interpolated into HTML. A repository-controlled `.c2c.json` can control `Workspace.name`, creating an HTML/script-injection path in the pairing page.

**Required behavior:**

- HTML-escape every dynamic value before interpolation.
- Add response headers that make script execution impossible on the pairing page even if future escaping regresses.
- Keep the current pairing form and OAuth flow fully functional.
- Do not add external JS/CSS resources.

**Required headers on authorization HTML responses:**

- `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'`
- `Cache-Control: no-store`
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`

### SH-02 — Misleading OAuth client identity on pairing page

**Current location:** `src/auth/oauth.ts`.

The page says "ChatGPT is requesting access" even though Dynamic Client Registration accepts arbitrary HTTPS clients.

**Required behavior:**

- Preserve arbitrary HTTPS client registration.
- Display the registered `client_name` (or `Unnamed OAuth client`) and the normalized redirect origin on the existing pairing page.
- Use provider-neutral wording: `<client> is requesting read-only access to workspace <workspace>`.
- Escape both values using the SH-01 escaping function.
- This is informational only; do not add a new confirmation screen or provider allowlist.

### SH-03 — Invalid-only OAuth scope request escalates to all scopes

**Current location:** `src/auth/store.ts`, `filterScopes()`; `src/auth/oauth.ts`, authorization endpoint.

Today a non-empty scope request containing zero recognized scopes falls back to all supported scopes.

**Required behavior:**

- Missing/blank `scope` continues to resolve to all `SUPPORTED_SCOPES` to preserve zero-config compatibility.
- A request containing at least one supported scope receives only the supported scopes it requested; unknown extras may be ignored to preserve compatibility.
- A non-empty request containing zero supported scopes MUST fail the authorization request with OAuth `invalid_scope` and MUST NOT create a pending authorization request.
- Default inclusion of `offline_access` when the scope parameter is omitted remains unchanged.

### SH-04 — Request-derived issuer/base URL and unvalidated OAuth `resource`

**Current locations:** `src/bridge/server.ts`, `getBaseUrl()`; `src/auth/oauth.ts`, authorization request parsing.

**Required behavior:**

- When a public tunnel URL exists, continue using it as the issuer/base URL.
- When no public URL exists, derive the local base URL from the bridge's known configured host and actual listening port, never from `Host` or forwarded request headers.
- If OAuth `resource` is supplied, normalize it as a URL and require it to equal the bridge MCP resource `${baseUrl}/mcp` (ignoring only an optional trailing slash). Reject a mismatched or malformed resource with `invalid_target` before storing the pending request.
- Omitted `resource` remains accepted for compatibility.
- Replace `app.set("trust proxy", true)` with loopback-only proxy trust so forwarded address data is trusted only from the local tunnel process.

### SH-05 — Sensitive path names leak through `git_status`

**Current locations:** `src/workspace/git.ts`, `gitStatus()`; `src/mcp/server.ts`, `git_status` tool.

`git_diff` applies `IgnoreRules`; `git_status` currently does not.

**Required behavior:**

- Change `gitStatus` to accept the same `GitTarget` abstraction used by `gitDiff`.
- Construct/use `IgnoreRules` exactly as `gitDiff` does.
- Filter sensitive paths out of `staged`, `unstaged`, `untracked`, and `conflicted` results.
- For rename/copy porcelain-v2 records, if either old or new path is sensitive, omit the record from all returned collections.
- Preserve branch/upstream/ahead/behind data.
- Update the MCP tool to call `gitStatus(workspace)` rather than `gitStatus(workspace.root)`.
- Continue exposing all non-sensitive status entries unchanged.

### SH-06 — Public `/health` exposes stable workspace fingerprint

**Current locations:** `src/bridge/server.ts`; `src/bridge/runtime.ts`; `tests/port.test.ts`.

`Workspace.id` is a truncated SHA-256 of the canonical absolute workspace path and is returned by public `/health`.

**Required behavior:**

- Do not change `Workspace.id`; it remains the internal stable key for runtime/auth/session storage.
- Public `/health` returns only `{ service, version, status }`.
- `findLiveBridge(workspaceId)` MUST validate a candidate bridge through loopback-only authenticated `GET /admin/info` using the `adminToken` already stored in that workspace's 0600 runtime-state file.
- A public/proxied request to `/admin/info` must continue returning 404.
- Port collision/fallback behavior remains unchanged.

### SH-07 — Automatic update channel lacks cryptographic authenticity

**Current locations:** `src/cli/index.ts` `update-check`; `skill/SKILL.md` update workflow.

The current updater trusts `origin` + `git pull --ff-only`. Fully automatic **end-user** updates are a locked feature, so the installed client must continue discovering and installing updates without user confirmation.

**Required architecture:** detached Ed25519-signed update channel using Node's built-in crypto; the signing private key MUST remain outside repository-controlled CI/workflows.

1. Add a pinned Ed25519 public key to the installed source tree. The updater always verifies using the public key from the **currently running/installed version**, never a key read from the candidate update.
2. Add a dedicated remote branch `c2c-update-channel` containing only:
   - `latest.json`
   - `latest.sig`
3. `latest.json` canonical format (UTF-8, LF, exactly one trailing newline):

```json
{"schema":1,"repository":"LeonAI-DO-YLCS/codex-with-chatgpt","branch":"main","commit":"<40-lowercase-hex-sha>","publishedAt":"<ISO-8601 UTC>"}
```

4. `latest.sig` is Base64 of an Ed25519 signature over the exact bytes of `latest.json`.
5. `c2c update-check`:
   - gets `refs/heads/main` and `refs/heads/c2c-update-channel` from `origin`;
   - fetches the update-channel ref into a private local ref;
   - reads `latest.json` + `latest.sig` with `git show`;
   - verifies Ed25519 signature using the pinned current-version key;
   - verifies manifest repository/branch/schema/SHA and that manifest commit equals the current remote `main` SHA;
   - if verification fails or publication is racing, reports no actionable update and does not record a successful daily check, so it retries later;
   - never treats an unsigned/unverified remote SHA as updateable.
6. Add `c2c update -w <workspace> --json` as the single secure automatic end-user update operation. It MUST:
   - repeat signature verification (never trust cached `update-check` output);
   - fetch the signed target commit;
   - require current `HEAD` to be an ancestor of the signed target (`git merge-base --is-ancestor`), preventing downgrade/non-fast-forward replacement;
   - preserve current local-edit behavior by stashing tracked + untracked changes before update;
   - record old HEAD for rollback;
   - fast-forward to the exact verified target SHA;
   - run `corepack pnpm install --frozen-lockfile` and `corepack pnpm build`;
   - if install/build fails, reset to old HEAD, restore old dependencies/build with `--frozen-lockfile`, and return a machine-readable failure without restarting the bridge;
   - on success, reinstall the Skill, run sandbox-allow, restart the workspace bridge, and refresh the update-check cache;
   - remain non-interactive for end users.
7. Add maintainer tooling to generate the signing keypair and publish a signed channel entry **from a trusted maintainer environment**. The private signing key MUST NOT be stored in this repository, a repository Actions secret, or any workflow/environment whose code is controlled by this repository. The publisher may run manually or from an independently controlled signing service/KMS later; the security requirement is separation from repository-controlled code.
8. Repository CI may run install/typecheck/test/build and emit the exact tested commit SHA, but it MUST NOT receive the signing private key. A maintainer signs only the exact commit that passed CI.
9. **Trust bootstrap:** the merge/install of the hardening release is the one-time bootstrap. Cryptographically verified automatic updates are guaranteed only after a version containing the pinned public key is installed.

This design protects users if `origin`, the source repository, or its normal CI workflow is modified without access to the independent signing key. Compromise of the signing key itself remains a root-of-trust compromise.

### SH-08 — Dependency selection is not deterministic enough for a security-sensitive auto-updater

**Current location:** `package.json`; update workflow.

**Required behavior:**

- Replace `"@modelcontextprotocol/sdk": "latest"` with the exact version already resolved by the baseline lockfile (`1.30.0`).
- Keep `pnpm-lock.yaml` committed.
- Every automatic install/update uses `corepack pnpm install --frozen-lockfile`.
- Dependency upgrades remain allowed, but must arrive through a signed repository update that intentionally modifies `package.json` and `pnpm-lock.yaml` together.
- Do not disable lifecycle scripts globally unless a separate compatibility review proves all supported present/future dependencies do not require them; signed + frozen dependency state is the required control for this plan.

## 4. Findings intentionally NOT patched because of locked decisions

| Audit finding / concern | Decision |
| --- | --- |
| Cloudflare can process tunneled MCP traffic | Accepted; Cloudflare remains part of the architecture. Document trust boundary accurately. |
| Secrets in ordinary readable files | Accepted; no content scanner/redactor. Existing path-level deny rules remain. |
| Any HTTPS OAuth client can register | Accepted; improve identity display and OAuth correctness, but no allowlist. |
| Cloud-plan prompt injection influencing Codex | C2C does not add execution filtering; preserve `UNTRUSTED_NOTE`; local agent policies are authoritative. |
| Exact outbound-data audit trail | Do not add. |
| Shared provider workspace/history | Preserve. |
| `workspace_info` returns package scripts | Preserve; removing command bodies would reduce planner context. |

## 5. Security invariants that must continue passing

- Bridge binds only to loopback.
- Admin endpoints require loopback + admin bearer token and reject proxied requests.
- MCP remains bearer-protected and workspace-bound.
- PKCE S256 remains mandatory.
- Authorization codes remain one-time and short-lived.
- Refresh tokens continue rotating and replay fails.
- Sensitive-path rules remain centralized in `IgnoreRules` and apply consistently to read/list/search/diff/status surfaces.
- Symlink and traversal protections remain unchanged.
- Tokens remain persisted only as hashes.
- Logs continue redacting token-/pairing-shaped secrets.
- No new MCP write/exec tool is introduced.

## 6. Definition of done

The hardening implementation is complete only when all of the following are true:

1. All SH-01 through SH-08 acceptance tests pass.
2. The existing full test suite passes unchanged except where tests are deliberately strengthened.
3. `pnpm typecheck`, `pnpm build`, and `pnpm test` all succeed.
4. A manual end-to-end smoke test confirms setup → tunnel → OAuth pairing → MCP read → Codex execute → cloud review still works.
5. An automatic signed end-user update succeeds without end-user confirmation.
6. A tampered/unsigned update is rejected without changing the installed checkout.
7. A failed install/build rolls back to the previous working version.
8. Public `/health` contains no workspace identifier/path-derived value.
9. A malicious `.c2c.json` workspace name renders as text and cannot execute HTML/script.
10. Sensitive filenames do not appear in MCP `git_status` output.
11. The update signing private key is demonstrably absent from repository files and repository-controlled workflow secrets.
12. No feature listed in §1 is removed, gated, or made provider-specific.
