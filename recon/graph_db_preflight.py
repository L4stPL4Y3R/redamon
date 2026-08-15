"""Preflight check for the graph_db bind mount (issue #169).

The orchestrator binds the host's ``graph_db`` source over ``/app/graph_db`` in
every spawned scan container, on top of the copy already baked into the image.
If it binds the WRONG host path, Docker does not fail: it silently auto-creates
an empty root-owned directory and mounts that. The empty directory shadows the
good baked-in copy, and Python then reports the graph package as an empty
namespace package:

    ImportError: cannot import name 'Neo4jClient' from 'graph_db' (unknown location)

That message names the symptom, not the cause, and it surfaces deep inside a
scan. This module turns it into one actionable line at startup instead.

The distinguishing signal is ``graph_db.__file__``: a real package has one, an
empty namespace package created by a bad bind mount does not.
"""

GRAPH_DB_CONTAINER_PATH = "/app/graph_db"


def check_graph_db() -> tuple[bool, str]:
    """Return ``(ok, message)`` for the graph_db package in this container.

    Never raises. ``ok`` is True only when ``Neo4jClient`` is actually importable;
    the message is empty in that case and human-actionable otherwise. Reachability
    of Neo4j itself is NOT checked here - that is a separate, recoverable
    condition already handled by ``verify_connection()`` at each call site.
    """
    import importlib.util

    # LOCATE before importing. graph_db/__init__.py pulls in the whole mixin stack
    # and the 'neo4j' driver, so a plain `import graph_db` conflates three very
    # different faults into one ImportError: not there, there-but-empty, and
    # there-but-its-dependencies-are-missing. Only the middle one is the bind-mount
    # bug, and only find_spec can tell them apart without executing anything.
    try:
        spec = importlib.util.find_spec("graph_db")
    except Exception as e:  # noqa: BLE001 - a preflight must never raise
        spec = None
        locate_error = e
    else:
        locate_error = None

    if spec is None:
        suffix = f" ({locate_error})" if locate_error else ""
        return False, (
            f"graph_db is not importable in this container{suffix}. Expected it at "
            f"{GRAPH_DB_CONTAINER_PATH}, either baked into the scan image or bound "
            f"there by the orchestrator."
        )

    if spec.origin is None or spec.origin == "namespace":
        # Namespace package: the directory exists but holds no __init__.py. This is
        # the issue #169 signature - an empty auto-created bind mount.
        # dict.fromkeys: every partial-recon module does its own
        # sys.path.insert(0, PROJECT_ROOT), so the search list arrives with the
        # same directory repeated ~20 times. Dedupe, keep order.
        search = list(dict.fromkeys(spec.submodule_search_locations or []))
        return False, (
            f"{GRAPH_DB_CONTAINER_PATH} is EMPTY - the orchestrator bound the wrong "
            f"host path over it and Docker auto-created an empty directory there, "
            f"hiding the copy baked into this image. Fix it on the HOST: add "
            f"'./graph_db:/app/graph_db:ro' to the recon-orchestrator volumes in "
            f"docker-compose.yml, then 'docker compose up -d recon-orchestrator' "
            f"(or set GRAPH_DB_PATH to the absolute host path of graph_db). "
            f"Search path used: {search}"
        )

    try:
        from graph_db import Neo4jClient  # noqa: F401
    except Exception as e:  # noqa: BLE001 - includes ImportError and any __init__ error
        return False, (
            f"graph_db was found at {spec.origin} but Neo4jClient could not be "
            f"imported ({type(e).__name__}: {e}). The package is present but "
            f"incomplete, or a dependency (the 'neo4j' driver) is missing from this "
            f"image. This is NOT the empty-bind-mount fault."
        )

    return True, ""


def require_graph_db(context: str = "Partial Recon") -> None:
    """Abort the run with an actionable message when graph_db is unusable.

    For entry points that cannot do anything useful without the graph (every
    partial-recon tool reads its inputs from it).
    """
    import sys

    ok, message = check_graph_db()
    if ok:
        return
    print(f"[!][{context}] graph_db preflight FAILED: {message}", flush=True)
    sys.exit(1)


def warn_if_graph_db_unusable(context: str = "Pipeline") -> bool:
    """Print a loud warning when graph_db is unusable. Returns True when it is OK.

    For the full pipeline, which wraps every graph import in try/except and so
    would otherwise finish "successfully" having written nothing to Neo4j.
    """
    ok, message = check_graph_db()
    if ok:
        return True
    print(f"[!][{context}] " + "=" * 63, flush=True)
    print(f"[!][{context}] graph_db is UNUSABLE - NO results will reach the graph.", flush=True)
    print(f"[!][{context}] {message}", flush=True)
    print(f"[!][{context}] " + "=" * 63, flush=True)
    return False
