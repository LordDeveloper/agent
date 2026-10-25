#!/usr/bin/env python3
"""Cut the next agent release and push the tag to GitHub.

The published git tag is the source of truth. Source files can lag behind
(they stayed on 0.4.104 while tags moved on), so this script never bumps
the number written in the tree. It reads tags from origin, picks the next
version, writes that version, commits, tags, and pushes.

Pushing a v* tag starts .github/workflows/release.yml, which builds the
Linux binaries and creates the GitHub Release.

Usage (from the agent repo, or via this file's path):

    python scripts/release.py --dry-run
    python scripts/release.py --message "restore peers in one apply"
    python scripts/release.py --minor
    python scripts/release.py --version 0.5.0
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

VERSION_FILES = (
    "src/agent/__init__.py",
    "pyproject.toml",
)

TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
VERSION_ASSIGNMENT = {
    "src/agent/__init__.py": re.compile(r'^(__version__\s*=\s*")[^"]*(")\s*$', re.M),
    "pyproject.toml": re.compile(r'^(version\s*=\s*")[^"]*(")\s*$', re.M),
}


@dataclass(frozen=True, order=True)
class SemVer:
    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @property
    def tag(self) -> str:
        return f"v{self}"

    def bump(self, part: str) -> SemVer:
        if part == "major":
            return SemVer(self.major + 1, 0, 0)
        if part == "minor":
            return SemVer(self.major, self.minor + 1, 0)
        if part == "patch":
            return SemVer(self.major, self.minor, self.patch + 1)
        raise ValueError(part)


def die(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
    except FileNotFoundError:
        die("git is not installed or not on PATH.")
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        die(f"git {' '.join(args)} failed:\n{detail}")
    return result


def parse_tag(name: str) -> SemVer | None:
    match = TAG_RE.match(name.strip())
    if not match:
        return None
    return SemVer(*(int(part) for part in match.groups()))


def parse_version(value: str) -> SemVer:
    parsed = parse_tag(f"v{value.strip().lstrip('v')}")
    if parsed is None:
        die(f"Version must look like 0.4.110 (got {value!r}).")
    return parsed


def origin_versions() -> list[SemVer]:
    result = git("ls-remote", "--tags", "origin")
    found: list[SemVer] = []
    for line in result.stdout.splitlines():
        if "\t" not in line:
            continue
        ref = line.split("\t", 1)[1].strip()
        if ref.endswith("^{}"):
            continue
        parsed = parse_tag(ref.removeprefix("refs/tags/"))
        if parsed is not None:
            found.append(parsed)
    return found


def source_version() -> str:
    text = (ROOT / "src/agent/__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else "unknown"


def current_branch() -> str:
    result = git("symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    branch = result.stdout.strip()
    if result.returncode != 0 or not branch:
        die("Detached HEAD. Check out main before cutting a release.")
    return branch


def ensure_release_branch(branch: str, allow_any: bool) -> None:
    if branch != "main" and not allow_any:
        die("Releases are cut from main. Pass --allow-any-branch to override.")


def ensure_not_behind(branch: str) -> None:
    remote_ref = f"origin/{branch}"
    if git("rev-parse", "--verify", "--quiet", remote_ref, check=False).returncode != 0:
        return
    behind = git("rev-list", "--count", f"HEAD..{remote_ref}").stdout.strip()
    if behind and int(behind) > 0:
        die(
            f"{remote_ref} is {behind} commit(s) ahead of HEAD.\n"
            f"Update first, then run this again:\n"
            f"  git pull --rebase origin {branch}"
        )


def ensure_not_merging() -> None:
    git_dir = Path(git("rev-parse", "--absolute-git-dir").stdout.strip())
    markers = ("MERGE_HEAD", "REBASE_HEAD", "CHERRY_PICK_HEAD", "rebase-merge", "rebase-apply")
    for name in markers:
        if (git_dir / name).exists():
            die(f"Git is in the middle of another operation ({name}). Finish it before releasing.")


def local_tag_sha(tag: str) -> str | None:
    result = git("rev-parse", "--verify", "--quiet", f"refs/tags/{tag}", check=False)
    if result.returncode != 0:
        return None
    # Annotated tags resolve to the tag object. Peel to the commit.
    peeled = git("rev-parse", "--verify", "--quiet", f"{tag}^{{}}", check=False)
    sha = (peeled.stdout if peeled.returncode == 0 else result.stdout).strip()
    return sha or None


def head_sha() -> str:
    return git("rev-parse", "HEAD").stdout.strip()


def is_secret(path: str) -> bool:
    name = path.replace("\\", "/").split("/")[-1].lower()
    if name == ".env.example":
        return False
    if name == ".env" or name.startswith(".env."):
        return True
    if name.endswith((".pem", ".p12", ".pfx")) or name.startswith("id_rsa"):
        return True
    return False


def write_version(version: SemVer) -> None:
    """Replace the version assignment in each known file, or abort before writing."""
    pending: list[tuple[Path, str]] = []
    rendered = str(version)
    for rel in VERSION_FILES:
        path = ROOT / rel
        if not path.is_file():
            die(f"Missing version file: {rel}")
        pattern = VERSION_ASSIGNMENT[rel]
        text = path.read_text(encoding="utf-8")
        if pattern.search(text) is None:
            die(f"Could not find the version assignment in {rel}.")
        new = pattern.sub(rf"\g<1>{rendered}\2", text, count=1)
        pending.append((path, new))
    for path, new in pending:
        path.write_text(new, encoding="utf-8", newline="\n")


def staged_names() -> list[str]:
    output = git("diff", "--cached", "--name-only", "--diff-filter=ACMRD").stdout
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def worktree_status() -> str:
    return git("status", "--porcelain").stdout.strip()


def stage_release() -> list[str]:
    git("add", "-A")
    names = staged_names()
    blocked = [name for name in names if is_secret(name)]
    if blocked:
        git("reset", "-q", "HEAD")
        die("Refusing to commit secret-looking paths:\n  " + "\n  ".join(blocked))
    return names


def commit_release(subject: str) -> bool:
    names = stage_release()
    if not names:
        return False
    print("Committing:")
    for name in names:
        print(f"  {name}")
    git("commit", "-m", subject)
    return True


def release_page(tag: str) -> str:
    url = git("remote", "get-url", "origin").stdout.strip()
    url = re.sub(r"\.git$", "", url)
    url = re.sub(r"^git@github\.com:", "https://github.com/", url)
    url = re.sub(r"^ssh://git@github\.com/", "https://github.com/", url)
    return f"{url}/releases/tag/{tag}"


def push_release(branch: str, tag: str) -> None:
    print(f"Pushing {branch}...")
    git("push", "origin", f"HEAD:refs/heads/{branch}")
    print(f"Pushing {tag}...")
    git("push", "origin", f"refs/tags/{tag}")


def choose_version(args: argparse.Namespace, published: list[SemVer]) -> SemVer:
    current = max(published) if published else SemVer(0, 0, 0)
    if args.version:
        chosen = parse_version(args.version)
        if published and chosen <= current:
            die(f"{chosen.tag} is not newer than the latest origin tag {current.tag}.")
        return chosen
    part = "major" if args.major else "minor" if args.minor else "patch"
    if not published and part == "patch":
        die("origin has no vX.Y.Z tag. Pass --version explicitly for the first release.")
    return current.bump(part)


def subject_for(version: SemVer, message: str | None) -> str:
    subject = f"Release {version.tag}"
    note = (message or "").strip()
    if note:
        subject = f"{subject}: {note}"
    return subject


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bump the agent version from the latest GitHub tag, then push the new tag.",
    )
    bump = parser.add_mutually_exclusive_group()
    bump.add_argument("--patch", action="store_true", help="Bump the patch number (default)")
    bump.add_argument("--minor", action="store_true", help="Bump the minor number and reset patch")
    bump.add_argument("--major", action="store_true", help="Bump the major number and reset the rest")
    bump.add_argument("--version", metavar="X.Y.Z", help="Publish this exact version")
    parser.add_argument(
        "--message",
        "-m",
        default=None,
        help="Short reason appended to the release commit subject",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the version and the files that would be committed, then stop",
    )
    parser.add_argument(
        "--allow-any-branch",
        action="store_true",
        help="Allow a release from a branch other than main",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not (ROOT / ".git").exists():
        die(f"{ROOT} is not the agent git checkout.")

    branch = current_branch()
    ensure_release_branch(branch, args.allow_any_branch)
    ensure_not_merging()

    print("Fetching origin...")
    git("fetch", "origin", "--tags")
    ensure_not_behind(branch)

    published = origin_versions()
    latest = max(published) if published else None
    version = choose_version(args, published)
    tag = version.tag
    in_source = source_version()
    subject = subject_for(version, args.message)

    print(f"Latest origin tag:  {latest.tag if latest else '(none)'}")
    print(f"Version in source:  {in_source}")
    print(f"Next release:       {tag}")
    print(f"Branch:             {branch}")
    print(f"Commit:             {subject}")

    if args.dry_run:
        print("Dry run. Version files and git are unchanged.")
        status = worktree_status()
        if status:
            print("Worktree that would be included:")
            print(status)
        else:
            print("Worktree is clean. The commit would only update the version files.")
        return 0

    on_origin = any(item.tag == tag for item in published)
    if on_origin:
        die(f"{tag} is already on origin.")

    existing = local_tag_sha(tag)
    if existing and existing != head_sha():
        die(
            f"Local tag {tag} already points at {existing[:12]}, not HEAD.\n"
            "Delete it if that attempt should be discarded, then run this again:\n"
            f"  git tag -d {tag}"
        )
    if existing:
        if worktree_status() or source_version() != str(version):
            die(
                f"Local tag {tag} already points at HEAD, but the worktree does not match it.\n"
                "To include the current files, delete the tag and rerun:\n"
                f"  git tag -d {tag}\n"
                "  python scripts/release.py\n"
                "To publish the tag that is already on HEAD:\n"
                f"  git push origin HEAD:refs/heads/{branch}\n"
                f"  git push origin refs/tags/{tag}"
            )
        print(f"{tag} is already on HEAD. Pushing the previous attempt.")
        push_release(branch, tag)
        print(f"Pushed {tag}.")
        print("GitHub Actions builds the binaries and creates the release from this tag.")
        print(release_page(tag))
        return 0

    write_version(version)
    commit_release(subject)
    if local_tag_sha(tag):
        die(f"{tag} appeared during the commit. Refusing to move it.")
    git("tag", "-a", tag, "-m", subject)
    print(f"Tagged {tag} -> {head_sha()[:12]}")

    push_release(branch, tag)
    print(f"Pushed {tag}.")
    print("GitHub Actions builds the binaries and creates the release from this tag.")
    print(release_page(tag))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
