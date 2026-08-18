# TruffleHog scan targets

Local targets for the TruffleHog sources that can read from disk. Put a file or
a repository in the matching sub-folder and the scan can reach it with **no
network access at all**.

```
scanners/scan_targets/
  filesystem/   the `filesystem` source scans THIS, always
  git/          one sub-folder per repository, for the `git` source
  docker/       one .tar per image, for the `docker` source
```

## Why this exists rather than a free-text path

Every other TruffleHog source takes an operator-typed target (a URL, a host, an
image ref). A typed *local path* is different in kind: the scan container holds
one credential in `/work/job.json`, so a source that could be pointed at
`file:///work/job.json` would read that token and report it back as a finding.
The container is hardened precisely so a compromise finds nothing but the key the
operator already aimed at the target.

So the path is never typed. The operator names a folder or a file, the server
composes the path against the fixed mount below, and the name is validated to a
single path segment: no `/`, no `..`, no absolute paths.

The directory is mounted **read-only** at `/scan-targets` inside the scan
container, and reaches it through the orchestrator's own bind mount - never a
derived host path, because a bind source Docker cannot find is not an error, it
is silently an empty directory.

## Using it

### filesystem

Drop anything into `filesystem/`. The source has no target field: it always
scans this folder.

### git

One repository per sub-folder. Either shape works, but they are NOT
interchangeable - a bare/mirror clone needs the **Bare repository** toggle on,
and without it the scan fails with `failed to stat .git`.

```bash
cd scanners/scan_targets/git

# working clone -> leave "Bare repository" OFF
git clone https://example.com/some/repo.git myrepo

# bare/mirror clone -> turn "Bare repository" ON
git clone --mirror https://example.com/some/repo.git myrepo.git
```

Then set the git source's **Local repository** field to the folder name. Leave
the Repository URI empty - a source may have one or the other, never both.

Ownership does not matter: the scan mounts a gitconfig that marks the tree safe,
because git otherwise refuses a repository owned by another uid and the clone
fails outright.

### docker

One image tarball per file:

```bash
docker save myimage:latest -o scanners/scan_targets/docker/myimage.tar
```

Then set the docker source's **Local image tarballs** field to `myimage.tar`.

## Do not commit real secrets

The whole point of a fixture here is to hold something a detector will fire on,
which makes it exactly the kind of file that must never contain a real
credential. Synthetic values only - see `CONTRIBUTING.md` -> "Legal and Ethical
Responsibilities". Everything in the sub-folders is git-ignored for that reason;
only this README and the `.gitkeep` files are tracked.

Note that a synthetic secret can only ever come back **unverified**: verification
calls the owning API, and a made-up key is rejected. Exercising the `verified`
path needs a real, live, throwaway credential, which must never be committed.
