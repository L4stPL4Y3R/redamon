"""Recovery for a deep-analysis artifact that fails the DIRTY->CLEAN gate.

GuardDog output quotes attacker-authored package source, so the artifact it
produces has to clear `validate_artifact` before anything trusted reads it.
When it does NOT clear the gate, the naive response - drop the whole
`suspicious` list and carry on - is a security bug, not a safe default:

    A package GuardDog never actually analysed is recorded as a `soft_error`
    finding precisely so it cannot read as behaviourally clean. Wiping the
    list wholesale deletes those markers too, so ONE malformed finding turns
    every un-analysed package back into an apparently-clean one.

That was found and fixed in the L2 recon path (D1) and then silently NOT
ported to the L1 standalone scan, which kept the wholesale wipe. Two copies of
one security invariant is how the drift happened, so the logic lives here once
and both layers call it.

The two callers differ in how they enumerate flagged packages and how they
shape a soft-error finding, so those are injected rather than duplicated.
"""

__all__ = ["recover_invalid_deep_artifact"]


def recover_invalid_deep_artifact(artifact, exc, *, validate, flagged_specs,
                                  add_soft_error, label="deep analysis"):
    """Salvage what validates; re-mark everything else as NOT analysed.

    Returns the revalidated artifact. Raises only if even the salvaged artifact
    cannot be validated, which would mean the damage is outside `suspicious`.

    `validate`       - validate_artifact (raises on a bad artifact)
    `flagged_specs`  - callable(artifact) -> [spec] (the deep-analysis input set)
    `add_soft_error` - callable(artifact, spec, message)
    """
    bad = list(artifact.get("suspicious") or [])

    # Probe each finding on its own: the artifact is rejected as a whole, so the
    # only way to learn WHICH entries are hostile is to validate them one at a
    # time. Everything that clears the gate is kept - a real GuardDog hit must
    # not be lost because a sibling entry was malformed.
    kept = []
    for finding in bad:
        probe = dict(artifact, suspicious=[finding])
        try:
            validate(probe)
            kept.append(finding)
        except Exception:
            pass

    artifact["suspicious"] = kept
    artifact.setdefault("errors", []).append(
        "{}: dropped {} unvalidatable finding(s): {}".format(
            label, len(bad) - len(kept), exc))

    # Any flagged package that no longer has a finding was either never analysed
    # or lost its result. Both mean "unknown", and unknown must never render as
    # clean.
    covered = {(f.get("name"), f.get("version")) for f in kept}
    for spec in flagged_specs(artifact):
        if (spec.get("name"), spec.get("version")) not in covered:
            add_soft_error(artifact, spec,
                           "{} result failed validation and was dropped; "
                           "package NOT analysed".format(label))

    return validate(artifact)
