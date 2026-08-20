"""
Tenant-scoping helpers for Cypher queries.

Single source of truth for:
- Inline (user_id, project_id) injection into every node pattern.
- Fail-closed verification that a query really is scoped before it runs.
- Read-only enforcement (write-clause and write-procedure detection).

Imported by both the agent (agentic.tools.Neo4jToolManager) and the
kali-sandbox CLI (mcp/servers/redagraph.py).

Why the scanner instead of one regex: scoping used to be a single
`\\((\\w+):(\\w+)...\\)` substitution, which only recognised `(var:Label)`.
Every other shape the text-to-Cypher LLM can emit - `(n)` with the label
tested in the WHERE, `(n:A:B)`, a backticked label, `(n {prop: 1})` - matched
nothing, so the query ran completely unscoped and returned every tenant's
nodes. That was observed live: an agent asked for "all malicious packages"
reported 4, one of which belonged to a different project.

Injection is therefore best-effort over ALL node-pattern shapes, and
`find_unscoped_node_pattern` is the backstop: anything that still cannot be
proven scoped must not be executed. Callers should use `scope_query`, which
does both.
"""

import re
from typing import Iterator, List, Optional, Tuple

_WRITE_CLAUSE_RE = re.compile(
    r'\b(CREATE|MERGE|DELETE|DETACH\s+DELETE|SET|REMOVE|DROP|ALTER|'
    r'LOAD\s+CSV|START\s+DATABASE|STOP\s+DATABASE|GRANT|DENY|REVOKE|'
    r'ENABLE\s+SERVER|DEALLOCATE|REALLOCATE|TERMINATE)\b',
    re.IGNORECASE,
)

_WRITE_PROCEDURE_RE = re.compile(
    r'\bCALL\s+(apoc\.(create|merge|refactor|periodic|trigger|schema|atomic)|'
    r'apoc\.cypher\.(runWrite|doIt)|dbms\.)\b',
    re.IGNORECASE,
)

TENANT_PARAMS = {"tenant_user_id", "tenant_project_id"}
TENANT_PROPS = "user_id: $tenant_user_id, project_id: $tenant_project_id"

#: Labels holding GLOBAL reference data - the public NVD/MITRE catalogue. Each
#: is UNIQUE on its natural id, so there is exactly one node per CVE for the
#: whole database and it carries no tenant property at all. Injecting a tenant
#: filter on one matches nothing, which made the agent blind to every CVE, CWE
#: and CAPEC in the graph.
#:
#: Exempt because they hold no per-tenant data, not because scoping is
#: inconvenient. Two guards keep the exemption from becoming a hole:
#:   - a pattern qualifies only when EVERY label it names is on this list, and
#:     only for a plain `:A` / `:A:B` conjunction. A label EXPRESSION never
#:     qualifies, because `(n:!CVE)` means every node that is NOT a CVE.
#:   - the QUERY must still carry at least one tenant-scoped pattern
#:     (`find_unscoped_node_pattern`), so reference nodes are reachable only by
#:     traversing from the caller's own data. `MATCH (c:CVE) RETURN c` on its
#:     own is still refused: which CVEs exist in the database is itself a weak
#:     signal about what other tenants have scanned.
GLOBAL_REFERENCE_LABELS = frozenset({"CVE", "MitreData", "Capec"})

#: A plain label conjunction and nothing else. Backticks are refused rather than
#: unquoted: a backticked label may contain ':' and would break the split below,
#: and no reference label needs quoting.
_SIMPLE_LABELS_RE = re.compile(r'^(?:\s*:\s*[A-Za-z_][A-Za-z0-9_]*)+$')

# A Cypher identifier: bare, or backtick-quoted (which may contain spaces).
_IDENT = r'(?:`[^`]*`|[A-Za-z_][A-Za-z0-9_]*)'

# The inside of a node pattern: optional variable, optional label expression
# (`:A`, `:A:B`, `:A|B`), optional inline property map.
_NODE_INNER_RE = re.compile(
    r'^\s*(?P<var>' + _IDENT + r')?'
    r'(?P<labels>(?:\s*[:|&!]\s*' + _IDENT + r')*)'
    r'\s*(?P<props>\{.*\})?\s*$',
    re.DOTALL,
)

_WORD_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')

# Clauses whose operand is a pattern, and the clauses that end one. Tracking
# this is what tells a node pattern apart from a parenthesised expression:
# `(n)` after MATCH is a node, `(n)` in a RETURN list is not.
_REGION_START = frozenset({'MATCH', 'MERGE', 'CREATE'})
_REGION_END = frozenset({
    'WHERE', 'RETURN', 'WITH', 'UNWIND', 'CALL', 'ORDER', 'SKIP', 'LIMIT',
    'DELETE', 'DETACH', 'SET', 'REMOVE', 'FOREACH', 'UNION', 'YIELD', 'ON',
    'USING', 'AS',
})


def find_disallowed_write_operation(cypher: str) -> Optional[str]:
    """Return a disallowed write clause/procedure name, or None for read-only Cypher."""
    proc_match = _WRITE_PROCEDURE_RE.search(cypher)
    if proc_match:
        return proc_match.group(1)

    match = _WRITE_CLAUSE_RE.search(cypher)
    if match:
        return re.sub(r'\s+', ' ', match.group(1).upper())

    return None


class TenantScopeError(Exception):
    """A query could not be proven tenant-scoped and must not be executed.

    Raised by `scope_query`. Callers that regenerate Cypher (the query_graph
    retry loop) should feed the message back to the model; callers that do not
    should surface it as a refusal. Never fall back to running the query.
    """


def code_positions(cypher: str) -> Tuple[List[bool], List[int]]:
    """Per character: is it executable code, and what brace depth is it at.

    Code means outside string literals (', ", `) and outside `//` and `/* */`
    comments, so a keyword or bracket quoted inside a literal is never mistaken
    for syntax. Depth counts `{ }` nesting, which tells a subquery body apart
    from the top level.
    """
    n = len(cypher)
    is_code = [False] * n
    depth = [0] * n
    current_depth = 0
    i = 0
    while i < n:
        ch = cypher[i]
        if ch == '/' and i + 1 < n and cypher[i + 1] == '/':
            newline = cypher.find('\n', i)
            i = n if newline == -1 else newline + 1
            continue
        if ch == '/' and i + 1 < n and cypher[i + 1] == '*':
            close = cypher.find('*/', i + 2)
            i = n if close == -1 else close + 2
            continue
        if ch in ("'", '"', '`'):
            quote = ch
            i += 1
            while i < n:
                if cypher[i] == '\\':
                    i += 2
                    continue
                if cypher[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == '}':
            current_depth = max(0, current_depth - 1)
        is_code[i] = True
        depth[i] = current_depth
        if ch == '{':
            current_depth += 1
        i += 1
    return is_code, depth


def _matching_paren(cypher: str, open_idx: int, is_code: List[bool]) -> Optional[int]:
    """Index of the `)` closing the `(` at open_idx, or None if unbalanced."""
    depth = 0
    for i in range(open_idx, len(cypher)):
        if not is_code[i]:
            continue
        if cypher[i] == '(':
            depth += 1
        elif cypher[i] == ')':
            depth -= 1
            if depth == 0:
                return i
    return None


def _is_function_call(cypher: str, open_idx: int) -> bool:
    """True when the `(` at open_idx opens a call, not a node pattern.

    A call is written with no space before the paren (`count(*)`, `collect(p)`),
    while a pattern always follows whitespace or a relationship arrow. Checking
    the IMMEDIATE previous character rather than the previous token matters:
    `MATCH (n)` is preceded by the keyword MATCH, which would otherwise read as
    a function name and leave the pattern unscoped.
    """
    if open_idx == 0:
        return False
    prev = cypher[open_idx - 1]
    return prev.isalnum() or prev in '_`'


def _prev_code_char(cypher: str, before: int, is_code: List[bool]) -> Optional[str]:
    for i in range(before - 1, -1, -1):
        if not is_code[i]:
            return '`'  # a backticked identifier ended here
        if not cypher[i].isspace():
            return cypher[i]
    return None


def _next_code_char(cypher: str, start: int, is_code: List[bool]) -> Optional[str]:
    for i in range(start, len(cypher)):
        if not is_code[i]:
            return '`'
        if not cypher[i].isspace():
            return cypher[i]
    return None


def _iter_node_patterns(cypher: str) -> Iterator[Tuple[int, int, str, bool]]:
    """Yield (start, end, inner, is_parseable) for every node-pattern candidate.

    A candidate is a parenthesised group that is either inside a pattern clause
    (MATCH / OPTIONAL MATCH / MERGE / CREATE) or adjacent to a relationship
    arrow, and is not a function call. `is_parseable` is False when the group
    does not parse as a node pattern - those are never rewritten, but they are
    reported as unscoped so an unrecognised shape fails closed instead of
    silently running unfiltered.
    """
    is_code, _ = code_positions(cypher)
    n = len(cypher)
    in_pattern_region = False
    i = 0
    while i < n:
        if not is_code[i]:
            i += 1
            continue
        ch = cypher[i]
        if ch.isalpha() or ch == '_':
            word_match = _WORD_RE.match(cypher, i)
            word = word_match.group(0).upper()
            if word in _REGION_START:
                in_pattern_region = True
            elif word in _REGION_END:
                in_pattern_region = False
            i = word_match.end()
            continue
        if ch == '(':
            close = _matching_paren(cypher, i, is_code)
            if close is None:
                i += 1
                continue
            prev = _prev_code_char(cypher, i, is_code)
            is_call = _is_function_call(cypher, i)
            following = _next_code_char(cypher, close + 1, is_code)
            arrow_adjacent = (
                (prev is not None and prev in '-><]')
                or (following is not None and following in '-<')
            )
            if not is_call and (in_pattern_region or arrow_adjacent):
                inner = cypher[i + 1:close]
                yield (i, close + 1, inner, bool(_NODE_INNER_RE.match(inner)))
            # Keep scanning INSIDE the group: patterns nest in predicates such
            # as `size((n)-->())`.
            i += 1
            continue
        i += 1


def _pattern_has_tenant_props(inner: str) -> bool:
    return "$tenant_user_id" in inner and "$tenant_project_id" in inner


def _is_global_reference_pattern(inner: str) -> bool:
    """True when the pattern names ONLY labels from GLOBAL_REFERENCE_LABELS.

    Strict by design; see the note on GLOBAL_REFERENCE_LABELS. An unlabelled
    pattern, a mixed one such as `(n:CVE:Domain)`, and any label expression
    (`:A|B`, `:!A`, `:A&B`) all fail this and are scoped as normal.
    """
    match = _NODE_INNER_RE.match(inner)
    if not match:
        return False
    raw = (match.group('labels') or '').strip()
    if not raw or not _SIMPLE_LABELS_RE.match(raw):
        return False
    labels = [part.strip() for part in raw.split(':') if part.strip()]
    return bool(labels) and all(label in GLOBAL_REFERENCE_LABELS for label in labels)


def _with_tenant_props(inner: str) -> str:
    match = _NODE_INNER_RE.match(inner)
    var = (match.group('var') or '').strip()
    labels = (match.group('labels') or '').strip()
    props = match.group('props')

    if props is not None:
        body = props.strip()[1:-1].strip()
        new_props = f"{{{body}, {TENANT_PROPS}}}" if body else f"{{{TENANT_PROPS}}}"
    else:
        new_props = f"{{{TENANT_PROPS}}}"

    head = f"{var}{labels}"
    return f"({head} {new_props})" if head else f"({new_props})"


def inject_tenant_filter(cypher: str, user_id: str, project_id: str) -> str:
    """
    Inject mandatory user_id and project_id filters into a Cypher query.

    Adds tenant properties directly into each node pattern as inline property
    filters. This ensures filters are always in scope regardless of WITH clauses
    or query structure.

    Example:
        MATCH (d:Domain {name: "example.com"})
    becomes:
        MATCH (d:Domain {name: "example.com", user_id: $tenant_user_id, project_id: $tenant_project_id})

    Every node-pattern shape is covered, including unlabelled `(n)`, multi-label
    `(n:A:B)`, backticked labels and anonymous `()` endpoints. Best-effort by
    design: pair it with `find_unscoped_node_pattern` (or just call
    `scope_query`) so an unparseable pattern is refused rather than run.

    The caller must pass the parameters {"tenant_user_id": user_id,
    "tenant_project_id": project_id} when executing the returned query.
    """
    spans = []
    last_end = -1
    for start, end, inner, parseable in _iter_node_patterns(cypher):
        if not parseable or start < last_end:
            continue
        # A global reference pattern is left alone: these nodes carry no tenant
        # property, so a filter here matches nothing at all.
        if _pattern_has_tenant_props(inner) or _is_global_reference_pattern(inner):
            last_end = end
            continue
        spans.append((start, end, inner))
        last_end = end

    if not spans:
        return cypher

    out = []
    cursor = 0
    for start, end, inner in spans:
        out.append(cypher[cursor:start])
        out.append(_with_tenant_props(inner))
        cursor = end
    out.append(cypher[cursor:])
    return ''.join(out)


def find_unscoped_node_pattern(cypher: str) -> Optional[str]:
    """Return the first node pattern that is not tenant-scoped, or None.

    Run this on the query AFTER injection. A non-None result means the query
    would read across projects and must not be executed.
    """
    patterns = list(_iter_node_patterns(cypher))
    # Reference nodes are readable only from a query that is ITSELF anchored to
    # the caller's data. Without this, `MATCH (c:CVE) RETURN c.id` would hand
    # back every CVE in the database - no asset, no project, but still the union
    # of what every tenant has found.
    has_tenant_anchor = any(
        parseable and _pattern_has_tenant_props(inner)
        for _, _, inner, parseable in patterns
    )
    for start, end, inner, parseable in patterns:
        if not parseable:
            return cypher[start:end]
        if _pattern_has_tenant_props(inner):
            continue
        if has_tenant_anchor and _is_global_reference_pattern(inner):
            continue
        return cypher[start:end]
    return None


def has_labelled_node_pattern(cypher: str) -> bool:
    """True when at least one node pattern declares a label.

    A least-privilege control for the worker-facing /graph/exec endpoint: the
    kali-sandbox must name the labels it wants rather than dumping the graph
    with a bare `MATCH (n)`. Tenant isolation no longer depends on this -
    `scope_query` scopes unlabelled patterns too - so this is defence in depth
    for the least-trusted caller, not the isolation mechanism.
    """
    for _, _, inner, parseable in _iter_node_patterns(cypher):
        if not parseable:
            continue
        match = _NODE_INNER_RE.match(inner)
        if (match.group('labels') or '').strip():
            return True
    return False


def scope_query(cypher: str, user_id: str, project_id: str) -> str:
    """Inject tenant filters and refuse anything that is still unscoped.

    This is the only entry point callers should use before executing
    LLM-generated or worker-supplied Cypher.

    Raises:
        TenantScopeError: the query cannot be proven scoped to one project.
    """
    filtered = inject_tenant_filter(cypher, user_id, project_id)
    unscoped = find_unscoped_node_pattern(filtered)
    if unscoped:
        raise TenantScopeError(
            f"Query rejected: node pattern {unscoped.strip()} could not be scoped "
            f"to this project. Give every node pattern an explicit label, e.g. "
            f"MATCH (p:Package), instead of matching (n) and testing the label "
            f"in a WHERE clause."
        )
    return filtered
