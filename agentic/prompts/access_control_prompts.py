"""
RedAmon Broken Access Control / Authorization Bypass Prompts

Black-box workflow for OWASP A01:2021 Broken Access Control, structured on the
OWASP WSTG Authorization Testing categories (WSTG-ATHZ 4.5.1-4.5.5):
  - Bypassing authorization schema / function-level access (forced browsing)
  - Privilege escalation (vertical + horizontal)
  - Insecure Direct Object Reference (IDOR / BOLA)
  - Token / session authorization (JWT, cookies)
  - API / GraphQL / CORS authorization

This is the home skill for the large class of targets whose win condition is
DEFEATING AN ACCESS DECISION (reaching a resource, action, role, or object the
request is not supposed to be allowed) with NO injection / inclusion / template
surface. It sits alongside the injection skills (rce, sql_injection, xss, ssrf,
path_traversal); classification defers to those whenever an injection primitive
is the actual goal.

Design:
- The reliable detector for EVERY access-control class is a DIFFERENTIAL against
  a baseline (an authorized or a denied control request), so the workflow is
  measurement-first: capture the baseline, mutate one axis, diff the response.
- No project tunables: every choice here (which method, which header, whether to
  enumerate) is a runtime decision the agent makes from observed target
  behaviour, so it belongs in the prompt, not in settings.
- Fairness: this module is generic tradecraft written with NO source access. It
  teaches the MECHANIC (enumerate + diff), never any specific target's answer.
  Injected verbatim (no .format()). See `_inject_builtin_skill_workflow` in
  agentic/prompts/__init__.py for wiring.
"""


ACCESS_CONTROL_TOOLS = """
## ATTACK SKILL: BROKEN ACCESS CONTROL / AUTHORIZATION BYPASS

**CRITICAL: This attack skill has been CLASSIFIED as Broken Access Control (OWASP A01:2021).**
**Follow the measurement-first workflow below. The winning move for this class is
a DIFFERENTIAL you observe against the live target, not an external exploit you
read about. Do NOT spend iterations on CVE / PoC research while a direct probe is
one request away.**

This skill covers authorization and authentication bypasses that have NO
injection, inclusion, or template surface. It maps to the OWASP WSTG Authorization
tests: bypassing the authorization schema (forced browsing / function-level),
privilege escalation (vertical + horizontal), IDOR / object-level authorization,
token/session authorization (JWT, cookies), and API/GraphQL/CORS authorization.
If recon shows an access wall (a login prompt, a `401`/`403`, an "admin only"
gate, a resource or object you should not be able to reach) and there is no
SQL/command/template/file-read surface, work it here.

--------------------------------------------------------------------------------
## CORE PRINCIPLE: THE DIFFERENTIAL ORACLE

Access control is invisible without a comparison. For every test:
1. Capture a **baseline**: either an AUTHORIZED request (what success looks like)
   or a DENIED control request (what the block looks like: exact status, body
   length, body hash, key headers).
2. Send ONE mutated request that changes exactly one variable.
3. **Diff** it against the baseline. A mutation that moves a denied control toward
   success (403/401 -> 2xx/3xx, empty -> populated body, one user's data -> another
   user's data) IS the finding. Reason from the diff, never from a single response.

The strongest oracle is **two accounts** owning distinct objects (if credentials
or self-registration exist): what User A may see vs what User A can reach of User
B's is the ground truth for horizontal escalation.

**Prefer the captured-traffic (`proxy_*`) tools as your native oracle when HTTP
capture is on** (they are the built-in Burp-equivalent and remove hand-rolled
diffing): `proxy_search` / `proxy_sitemap` / `proxy_params` to mine what has
already been observed; **`proxy_replay`** to resend a real captured request with
ONE field changed (session cookie, object id, role field, method, header) - the
core access-control primitive; **`proxy_diff`** to structurally compare the
replayed response against its baseline (the differential, computed for you);
**`proxy_fuzz`** to run a Burp-Intruder sweep over one captured request (id
enumeration, header/verb sets). When capture is OFF, fall back to `execute_curl`
/ `execute_httpx` / `execute_ffuf` / `execute_code` for the same steps.

--------------------------------------------------------------------------------
## STOP CHECKS (the failures that waste a session for this class)
- **Target the concrete backing document, not only the directory.** Access
  decisions and responses routinely differ between a directory URL and the actual
  document the server serves for it, because a request to a directory re-triggers
  the server's default-document resolution (Apache `DirectoryIndex`, nginx `index`
  / `location` matching, IIS default document) and canonical redirects, and that
  internal index step re-applies the guard as an ordinary read. A rule scoped to a
  directory is therefore frequently defeated ONLY by requesting the backing
  document directly, where that indirection - and the re-applied guard - is gone.
  So probe BOTH the directory form AND each concrete document behind it.
- **When the directory is auth-gated and shows no usable body, you do not yet KNOW
  the backing document - discover it before concluding anything.** Read any
  `Location`/redirect, fingerprint the stack, and request the likely default /
  front-controller filenames for that stack DIRECTLY from your content-discovery
  wordlist (candidates span stacks: `index.<ext>`, `default.<ext>`, the framework
  front controller, `home.*`, `app.*`, ...). Every axis in Step 4 is only as good
  as the resource set you run it against; an empty concrete-document set is a
  discovery gap, never proof the surface is exhausted.
- **Enumerate exhaustively; never conclude from one or two tries.** This class is
  solved by sweeping an axis and reading the survivor, not by guessing the "right"
  value.
- **Control your own harness before blaming the target.** Build requests with
  `execute_code` (python `requests`) or `execute_curl`; fragile nested shell
  quoting silently mangles methods, headers, and bodies. A constant response
  across every variant usually means your request never actually changed.
- **Confirm a header/override is HONORED before believing the bypass** (see the
  Step 4 oracle). Many trust-header "bypasses" are false positives on back-ends
  that ignore the header.
- **Do not rat-hole on external CVE/PoC hunts** before the local differential
  sweep is on the record.
- **Commit to a logic/race vector; do not scatter into scanners.** Once evidence
  points to a business-logic, mass-assignment, or TOCTOU/race authorization bug (a
  concurrency/race theme, a check that sets state then re-reads it, a
  client-controlled trust field), concentrate on THAT vector with `execute_curl` /
  `execute_code`. Content-discovery fuzzers, credential brute-forcers, and
  CVE/version scanners do not solve logic or race bugs - running them here burns the
  budget the actual exploit needs.

--------------------------------------------------------------------------------
## MANDATORY WORKFLOW

### Step 1: Inventory the surface (reuse recon; do not re-scan blindly)
- `query_graph` for already-discovered endpoints, params, and auth state, and
  `proxy_search` / `proxy_sitemap` / `proxy_params` to mine any already-captured
  traffic for authed endpoints, hidden routes, and tamperable parameters.
- Crawl for hidden endpoints and admin functionality: `execute_katana` (or
  `execute_gau`) to collect URLs; `execute_jsluice` to pull endpoints, routes, and
  parameter names out of client JS (front-ends routinely name admin/API routes the
  UI never links). `execute_playwright` to render the app and read client-side-
  gated UI (buttons/links hidden by JS role checks still point at live endpoints).
- Surface admin/login/console panels with OSINT too: `google_dork` (e.g. inurl:admin
  / inurl:login / intitle:"index of") to find management interfaces the app does not
  link. On WordPress, `execute_wpscan` enumerates users (ready-made horizontal-
  escalation targets) and known auth issues.
- Discover hidden request parameters with `execute_arjun` on each endpoint (this
  is how you find `role` / `isAdmin` / `debug` / `uid` style fields the UI omits).

### Step 2: Establish the baseline oracle (per protected resource)
- Send the plain expected request; record exact status, `Content-Length`, a body
  hash, and notable headers. This control is what every mutation is diffed against.
- If you have or can register credentials, capture BOTH an authorized baseline and
  an unauthorized one so you can tell "granted" from "blocked" precisely.

### Step 2A: Authentication-logic bypass (login / credential forms)
When the wall is a LOGIN FORM (or any endpoint that compares submitted
credentials), test whether the credential CHECK itself is defeatable by the SHAPE
or TYPE of what you submit BEFORE assuming a valid secret must be guessed. These
are single cheap requests; the winning input is one you DISCOVER by sweeping the
menu and reading the differential, never a value you already know.
- **Baseline:** submit a deliberately WRONG credential pair and record the failed
  response (status, length, body hash). Every mutation below is diffed against it;
  the finding is any cell that moves the failed baseline toward success (the authed
  page, a role change, or the protected content / flag).
- **Per-field type/presence sweep.** For EVERY field the form submits (each
  username-like field, each password-like field, and any hidden/extra field), tested
  each field alone AND in combination, sweep this menu and diff every result. Do NOT
  pre-judge which field or which row wins - enumerate the whole matrix:
  | Row | What to submit for that field |
  |-----|-------------------------------|
  | absent   | omit the parameter entirely |
  | empty    | present with no value |
  | array    | send the field as an array-typed parameter |
  | boolean/number | scalar values such as `true` / `1` / `0` |
  | type-juggle | numeric-strings that collide under a loose `==` (e.g. distinct `0e`-prefixed hash-style strings) |
  | operator object | structured not-equal / always-true objects for NoSQL-style back-ends |
  | tautology | classic SQL / LDAP auth-bypass and wildcard strings |
- **Why this class exists:** a login built on a loose or type-confusable comparison
  (a language's loose `==`, a string-compare helper whose integer result is read as a
  boolean, or hash-equality on attacker-supplied input) accepts a whole EQUIVALENCE
  CLASS of inputs - so "find the right password" is the wrong frame: enumerate the
  menu and the class member that satisfies the check falls out of the diff. Build the
  requests with `execute_code` (python `requests`) or `execute_curl` (fragile shell
  quoting silently mangles typed/array params); with capture on, `proxy_replay` the
  failed login changing one field/row at a time and let `proxy_diff` score it.
- Only once this full matrix is on record WITHOUT a success differential does the
  credential genuinely need to be discovered - then, and only then, hand off to
  credential guessing / brute force.

### Step 3: Forced browsing / function-level access (WSTG 4.5.2 + 4.5.3 vertical)
- The app decides your role somewhere; test whether privileged FUNCTIONS are
  reachable without the role. Enumerate admin/privileged endpoints with
  `execute_ffuf` against function/word wordlists (e.g. SecLists
  `Discovery/Web-Content/*`), diffing status/length against the Step 2 control.
- Run `execute_nuclei` exposure/misconfiguration/default-login templates to catch
  exposed panels and known auth-bypass misconfigurations quickly.
- For every privileged action found in the UI as one role, replay it as a lower/no
  role and diff. Vertical escalation is confirmed when the privileged function
  executes for the unprivileged (or unauthenticated) caller.

### Step 4: 401 / 403 bypass sweep (verb + method-override + trust-header + path)
Run this whenever a resource returns 401/403. MANDATORY targeting: sweep each axis
against BOTH the directory URL AND every concrete backing document the directory
serves - not the directory alone. If no concrete document is in your set yet, STOP
and discover it first (see the STOP CHECK above: read redirects, fingerprint the
stack, request likely default / front-controller filenames directly); a guard
scoped to a directory commonly survives at the directory URL while failing on the
backing document, so sweeping only the directory (or guessed sibling paths) will
falsely read as "no bypass." Diff every response against the baseline:
- **Order within every axis: bare form FIRST, exotic LAST.** For each axis below,
  run the plainest unmodified variant and record its result BEFORE any encoded,
  normalized, null/whitespace-injected, chunked, or smuggled variant. The simplest
  request (a single verb on the plain path, one header, the raw path) is both the
  most likely bypass and the cheapest to confirm; jumping to encoded/exotic
  variants before the bare form is on record is exactly how a live bypass on the
  plain request gets skipped. Escalate to exotic variants only after the bare form
  of that axis is recorded for that resource.
- **The checklist is PER-RESOURCE; a newly discovered document RESETS it.** Axes
  you already swept against the parent directory (or any other path) do NOT count
  as swept against a different concrete document. Whenever you discover a new
  backing document, re-run the FULL axis set - starting with the bare verb sweep -
  against THAT resource specifically before drawing any conclusion about it. "I
  already tried verbs" is only true for the exact path you tried them on.
- **Make it a MATRIX, not a walk: build M x R and execute every cell.** Do not
  decide per-resource whether a sweep is "worth it" - that judgment is what fails,
  because a resource can look identically locked under your baseline method yet
  diverge under a different one. Instead form the set M = {every verb in the method
  sweep} and the set R = {the directory URL} UNION {every concrete document you have
  discovered}, then issue EVERY (method, resource) pair and diff each cell against
  the baseline. One cell that differs (a success status, a longer body, the
  protected content) is the bypass. `job_spawn` the whole matrix so cost is never a
  reason to prune it. Identical baseline-method responses across two resources are
  NOT permission to drop either from R: that sameness is exactly the pattern a
  method-scoped guard produces, and the divergence appears only in the non-baseline
  rows of the matrix.
- **HTTP method / verb tampering.** Enumerate the FULL method space, not the one
  or two you first tried: every standard verb, the WebDAV verbs, randomized-case
  verbs, and at least one syntactically valid NON-STANDARD token. A rule that
  guards only an explicit verb list serves any unlisted verb that still reaches
  the handler. Run this sweep against the plain concrete document directly (bare
  path, no encoding), not only against the directory.
- **Method-override headers.** Re-send the request with an override header naming
  a different verb (the common `X-HTTP-Method-Override` / `X-Method-Override` /
  `X-HTTP-Method` family) while keeping the wire method simple.
- **Trust / URL-rewrite headers.** Add, one at a time then combined, the headers a
  mis-scoped "internal only" or reverse-proxy rule may trust: URL-override
  (`X-Original-URL`, `X-Rewrite-URL`, `X-Original-Uri`, `X-Forwarded-Uri`) and
  client-origin (`X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`,
  `X-Forwarded-Host`, `X-Custom-IP-Authorization`, `Forwarded`, `Referer`).
  **MANDATORY oracle for URL-override headers:** first send the override pointing
  at a definitely-invalid path and confirm the back-end returns its OWN not-found
  (proving the back-end reads the header while the proxy did not), THEN point it at
  the restricted path. Skip the header if the invalid probe does not change the
  back-end's behaviour (it is not honored -> false positive).
- **Path normalization.** Sweep the normalization matrix comparing each to the
  baseline: trailing slash, trailing dot, doubled slashes, dot-segment insertions,
  semicolon path parameters, matrix/`;` suffixes, single and double URL-encoding of
  `.` and `/`, and overlong/unicode encodings. Proxy-vs-back-end normalization
  mismatches are exactly what these exercise.
- **Tooling.** With capture on, `proxy_replay` a denied request while changing
  one axis at a time and let `proxy_diff` score each against the baseline. If
  `kali_shell` is available and a 403/401-bypass tool is installed (e.g. nomore403
  / gobypass403), run it: these operationalize the whole verb+header+path matrix
  with built-in baseline capture and false-positive calibration. Otherwise drive
  the same matrix with `execute_curl` / `execute_httpx` (mass status/length
  diffing) / `execute_ffuf`. For a large mutation set, `job_spawn` the sweep and
  `job_wait` on it so you do not block.

### Step 5: IDOR / object-level authorization (WSTG 4.5.4 / BOLA; horizontal escalation)
- Map EVERY user-controllable object reference in URLs, params, JSON bodies,
  cookies, and headers: numeric ids, UUID/GUIDs, filenames, slugs, account numbers,
  tokens. References are NOT limited to numbers.
- For each, substitute a reference you should not own and diff. With two accounts,
  request User B's object as User A. The oracle: a `200 OK` returning another
  principal's object (vs the `403/401` a secure app returns) confirms IDOR/BOLA.
- Enumerate predictable refs with `execute_ffuf` (increment/decrement across
  encodings: decimal, hex, timestamps), or `proxy_fuzz` a captured object request
  over the id set; `job_spawn` large ranges. Discover unpredictable GUIDs via
  cross-references elsewhere in the app (listings, messages, exports), not blind
  guessing.
- Cover ALL operations, not just read: create / update / delete / export / and
  admin variants of the same object route. Script the two-principal differential
  with `execute_code` (python), or with capture on `proxy_replay` an authorized
  request under the other principal's session and `proxy_diff` the result.

### Step 6: Parameter / client-side / hidden-field / mass-assignment escalation
- When the role or entitlement is stored somewhere the client controls (hidden
  form field, cookie, preset query param, JSON field), tamper it and diff: submit
  a role/flag/level/id field flipped toward privilege. Use `execute_arjun`
  (Step 1) to surface the hidden field names first, then `execute_curl` to tamper.
- Mass assignment: add fields the API did not send you (role, owner, isVerified,
  price) to an update/create body and check whether the server binds them.
- Client-side-only enforcement: if `execute_playwright` shows the UI hides an
  action by JS but the underlying endpoint still exists, call the endpoint directly.
- **A privilege tamper still needs a valid session.** If flipping the
  role/entitlement field returns an AUTHENTICATION failure (a bad-login response)
  rather than an authorization denial, the blocking gate is auth, not authz - the
  tamper is likely correct but is firing without a logged-in principal. Do NOT
  abandon it: obtain ANY valid low-privilege credential first (Step 2A), then replay
  the exact tamper inside that authenticated request. To source a low-priv login
  cheaply, derive candidate usernames from role names, on-page labels, and endpoint
  paths (and their common short forms), and try trivial/derived passwords - vendor
  defaults, the username itself, and a short weak-password list - before escalating
  to heavier credential attacks.

### Step 7: Token / session authorization (JWT, cookies)
- Decode any JWT / bearer / session token (`execute_code`). Inspect claims for
  role/user/scope fields.
- **alg:none:** re-sign as unsigned (`alg` set to none) and strip the signature;
  if the server accepts it you control every claim. Servers that string-filter the
  value can sometimes be bypassed with mixed-case / alternate encodings of the
  algorithm name.
- **Weak HMAC secret:** if HS-signed, attempt an offline secret crack
  (`jwt_tool` or `hashcat` mode 16500 via `kali_shell`, or a python wordlist loop
  via `execute_code`); a recovered secret lets you forge any claim.
- **Algorithm/key confusion and `kid` abuse:** where a public key is obtainable,
  test RS->HS confusion; test `kid` for path/injection handling.
- **Claim tampering:** with any of the above, flip the role/identity claim and diff
  the authorized response.
- Plain cookies/session values that encode role (`admin=false`, `role=user`) are
  the same test without the crypto: tamper and diff.

### Step 8: API / GraphQL / CORS authorization
- REST/API: repeat Step 5 (BOLA) and test broken FUNCTION-level authz (BFLA) by
  calling privileged/admin API methods as a low-privilege principal; diff.
- GraphQL: run an introspection query to recover the schema and hidden operations;
  use field suggestions if introspection is disabled; then call
  mutations/queries you should not be authorized for.
- CORS: check whether the `Access-Control-Allow-Origin` reflects an arbitrary
  `Origin` with `Allow-Credentials: true` (a cross-origin read of authed data).

### Step 9: Business-logic / multi-step workflow
- For multi-step flows (checkout, password reset, approval), try skipping,
  reordering, or replaying steps, and forcing state transitions out of order.
- Diff the resulting state against the intended path; a reachable end-state without
  the gating step is the flaw.
- **Step-up / second-factor is often not re-enforced at the resource.** When access
  is multi-step (login -> OTP/2FA/email-verify/approval -> protected page), test
  whether the protected page independently re-checks EACH step or only trusts
  first-step state (e.g. a session role/flag set at login). Reach the protected
  resource carrying ONLY the first-step state and see if it serves the goal - a
  second factor gated on the login path alone is frequently never re-validated on the
  target page. A guessable or static second-factor value is a secondary finding;
  test the "not re-checked at all" case first.
- **TOCTOU / race-condition authorization (check-then-use).** When a handler
  VALIDATES state and then RE-READS or RE-USES that state later (same handler or a
  sibling), or when server-side state is shared across concurrent requests by a
  cookie/session id, there is a race window. Exploit it generically: (1) pin the
  exact check-then-use gap; (2) drive it with high parallelism aimed at same-instant
  arrival (a burst of simultaneous requests / an HTTP-pipelined batch), NOT
  sequential retries; (3) interleave the two operations that must race - the request
  that PASSES the check against the one that MUTATES the checked state - on the SAME
  shared session/context; (4) use any state-echo/observability view the app exposes
  (a debug/status/echo endpoint) to CONFIRM the intended change actually lands, and
  keep raising concurrency until it does.

--------------------------------------------------------------------------------
## CONFIDENCE SCORING + REPORTING
- **High** - the protected content / action / another principal's object was
  actually returned or performed (flag retrieved, admin function executed, User B's
  data read), reproduced cleanly against the baseline.
- **Medium** - a consistent status/length differential toward success across runs,
  but the sensitive content was not yet extracted.
- **Low** - a single-run anomaly or error-message disclosure only.
Report: the exact request that won (method, path, headers, body), the baseline it
was diffed against, and the class (WSTG category).

## FALSE-POSITIVE GATE (confirm before claiming)
- A trust-header bypass counts ONLY if the back-end demonstrably honored the header
  (the invalid-path oracle in Step 4 fired).
- A path-normalization/verb bypass counts ONLY if the response actually returns the
  protected content, not merely a different-but-still-denied status.
- An IDOR counts ONLY if the returned object provably belongs to a different
  principal, not a public/empty object that every role can see.
- Re-send any winning request once, cleanly, to confirm it is stable, not a
  transient backend error.

## ABANDONMENT GATE
Do NOT declare an access wall impassable until, per applicable step, you have on
record: for a login / credential form, the full authentication-logic type/presence
matrix of Step 2A (every row swept against every field, diffed) - an untried or
partial matrix means you have NOT earned a brute-force hand-off; the full
method-space sweep against BOTH the directory AND every concrete
backing document it serves (an EMPTY concrete-document set does NOT satisfy this -
it means you skipped discovery, so go identify the backing document(s) and sweep
them before giving up); the trust-header set WITH the honored-header oracle; the
path-normalization matrix; the object-reference substitution (with two principals
if available); the client-controlled-state tamper; and any token/JWT test. Only
when the applicable sweeps are recorded - against the real backing documents, not
just the directory root - may you reclassify or give up.

## FLAG HANDLING
When a winning response contains the flag, emit the LITERAL `FLAG{...}` value
exactly as it appears in that response body - never a placeholder, a summary, or a
re-typed guess. If the winning request's output was offloaded or truncated, re-
fetch it and read the literal value before you report or `complete`.
"""
