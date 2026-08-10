"""Stream a tool subprocess's output live while capturing a tail for errors.

The tool runners (garak/pyrit/giskard/promptfoo) are opaque during a long scan
because they were run with capture_output=True. run_streamed pipes their combined
stdout+stderr to OUR stdout in real time (-> container log -> orchestrator SSE ->
UI output panel), so per-probe progress is visible. It splits on both \\n and \\r
so tqdm-style progress bars surface, throttles to avoid spam, and enforces an
overall timeout even when the child is silent (via select). Never raises on a
non-zero exit -- the caller decides.
"""
from __future__ import annotations

import collections
import os
import select
import subprocess
import time


def run_streamed(cmd, env=None, timeout=None, tag="tool", throttle=0.4):
    """Run cmd, streaming '[tag] <line>' to stdout. Returns (returncode, tail)."""
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, bufsize=0)
    tail: collections.deque = collections.deque(maxlen=400)
    buf = b""
    start = time.monotonic()
    last_emit = [0.0]

    def emit(seg: bytes):
        s = seg.decode("utf-8", "replace").strip()
        if not s:
            return
        tail.append(s)
        now = time.monotonic()
        if now - last_emit[0] >= throttle:
            print(f"    [{tag}] {s[:240]}", flush=True)
            last_emit[0] = now

    fd = proc.stdout.fileno()
    try:
        while True:
            if timeout is not None and time.monotonic() - start > timeout:
                proc.kill()
                print(f"    [{tag}] TIMEOUT after {timeout}s", flush=True)
                return -1, "\n".join(list(tail)[-60:]) + f"\nTIMEOUT after {timeout}s"
            ready, _, _ = select.select([fd], [], [], 1.0)
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            buf += chunk
            # normalize CR progress redraws to newlines; keep the trailing partial
            parts = buf.replace(b"\r", b"\n").split(b"\n")
            buf = parts.pop()
            for line in parts:
                emit(line)
        if buf:
            emit(buf)
        proc.wait(timeout=5)
    except Exception as e:  # streaming must never crash the adapter
        try:
            proc.kill()
        except Exception:
            pass
        tail.append(f"stream error: {e}")
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
    rc = proc.returncode if proc.returncode is not None else -1
    return rc, "\n".join(list(tail)[-60:])
