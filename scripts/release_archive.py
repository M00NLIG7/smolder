#!/usr/bin/env python3
"""Build support and validation for registry-shaped Smolder release archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tarfile
import tomllib
from datetime import datetime, timezone
from typing import Any, NoReturn

REPOSITORY = "https://github.com/M00NLIG7/smolder"
RUST_VERSION = "1.85"
LICENSE = "MIT"
PACKAGES = {
    "smolder-proto": {
        "path": "smolder-proto",
        "dependencies": {},
    },
    "smolder-smb-core": {
        "path": "smolder-core",
        "dependencies": {
            "smolder-proto": ("smolder-proto", "=0.4.0"),
        },
    },
    "smolder": {
        "path": "smolder-tools",
        "dependencies": {
            "smolder-core": ("smolder-smb-core", "=0.4.0"),
            "smolder-proto": ("smolder-proto", "=0.4.0"),
        },
    },
}
PUBLISH_ORDER = ["smolder-proto", "smolder-smb-core", "smolder"]
SECRET_PATTERNS = {
    "private key": re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    "GitHub token": re.compile(
        rb"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})"
    ),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Slack token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "crates.io token": re.compile(rb"\bcio[A-Za-z0-9_-]{30,}\b"),
    "Cargo registry token assignment": re.compile(rb"CARGO_REGISTRY_TOKEN\s*="),
}
LOCAL_PATH_PATTERNS = {
    "macOS home path": re.compile(rb"/Users/[^/\s]+/"),
    "Linux home path": re.compile(rb"/home/[^/\s]+/"),
    "Windows home path": re.compile(rb"[A-Za-z]:\\Users\\[^\\\s]+\\"),
}
SUSPICIOUS_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
SUSPICIOUS_SUFFIXES = {".key", ".p12", ".pem", ".pfx"}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release archive validation failed: {message}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def archive_members(
    archive: pathlib.Path, expected_root: str
) -> list[tuple[str, bytes, int]]:
    members: list[tuple[str, bytes, int]] = []
    seen: set[str] = set()
    with tarfile.open(archive, "r:gz") as crate:
        for member in crate.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                fail(f"{archive.name} contains unsafe path {member.name!r}")
            if not path.parts or path.parts[0] != expected_root:
                fail(
                    f"{archive.name} contains a path outside {expected_root}/: {member.name!r}"
                )
            if member.name in seen:
                fail(f"{archive.name} contains duplicate member {member.name!r}")
            seen.add(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                fail(f"{archive.name} contains a non-regular member {member.name!r}")
            extracted = crate.extractfile(member)
            if extracted is None:
                fail(f"could not read {member.name!r} from {archive.name}")
            members.append((member.name, extracted.read(), member.mode))
    if not members:
        fail(f"{archive.name} is empty")
    return members


def install_archive(archive: pathlib.Path, registry: pathlib.Path) -> pathlib.Path:
    if not archive.is_file():
        fail(f"missing archive {archive}")
    archive_name = archive.name
    if not archive_name.endswith(".crate"):
        fail(f"archive does not end in .crate: {archive_name}")
    root_name = archive_name[: -len(".crate")]
    members = archive_members(archive, root_name)
    destination = registry / root_name
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True)

    file_hashes: dict[str, str] = {}
    prefix = f"{root_name}/"
    for member_name, data, mode in members:
        relative = member_name.removeprefix(prefix)
        if not relative:
            continue
        output = destination / pathlib.PurePosixPath(relative)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        output.chmod(mode & 0o777)
        file_hashes[relative] = sha256_bytes(data)

    checksum = {
        "files": dict(sorted(file_hashes.items())),
        "package": sha256_file(archive),
    }
    (destination / ".cargo-checksum.json").write_text(
        json.dumps(checksum, separators=(",", ":")), encoding="utf-8"
    )
    return destination


def dependency_tables(manifest: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    tables: list[tuple[str, dict[str, Any]]] = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = manifest.get(section)
        if isinstance(value, dict):
            tables.append((section, value))
    targets = manifest.get("target", {})
    if isinstance(targets, dict):
        for target_name, target in targets.items():
            if not isinstance(target, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                value = target.get(section)
                if isinstance(value, dict):
                    tables.append((f"target.{target_name}.{section}", value))
    return tables


def dependency_details(value: Any) -> tuple[str, str | None, str | None, str | None]:
    if isinstance(value, str):
        return value, None, None, None
    if not isinstance(value, dict):
        fail(f"dependency entry has unsupported shape: {value!r}")
    version = value.get("version")
    if not isinstance(version, str):
        fail(f"dependency entry is missing a version: {value!r}")
    package = value.get("package")
    path = value.get("path")
    registry = value.get("registry")
    return version, package, path, registry


def inspect_package(
    repo: pathlib.Path,
    archive: pathlib.Path,
    package_name: str,
    version: str,
    archive_checksums: dict[str, str],
    head: str,
) -> dict[str, Any]:
    expected_root = f"{package_name}-{version}"
    members = archive_members(archive, expected_root)
    files = {
        name.removeprefix(f"{expected_root}/"): data for name, data, _mode in members
    }
    required = {
        ".cargo_vcs_info.json",
        "Cargo.lock",
        "Cargo.toml",
        "Cargo.toml.orig",
        "README.md",
    }
    missing = sorted(required - files.keys())
    if missing:
        fail(f"{archive.name} is missing required files: {', '.join(missing)}")
    if "src/lib.rs" not in files:
        fail(f"{archive.name} does not contain src/lib.rs")

    for relative, data in files.items():
        path = pathlib.PurePosixPath(relative)
        lower_name = path.name.lower()
        if lower_name in SUSPICIOUS_NAMES or path.suffix.lower() in SUSPICIOUS_SUFFIXES:
            fail(f"{archive.name} contains credential-like file {relative!r}")
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(data):
                fail(
                    f"{archive.name}:{relative} matched high-confidence {label} pattern"
                )
        for label, pattern in LOCAL_PATH_PATTERNS.items():
            if pattern.search(data):
                fail(f"{archive.name}:{relative} contains a workstation-local {label}")

    manifest = tomllib.loads(files["Cargo.toml"].decode("utf-8"))
    original = tomllib.loads(files["Cargo.toml.orig"].decode("utf-8"))
    package = manifest.get("package", {})
    expected_metadata = {
        "name": package_name,
        "version": version,
        "repository": REPOSITORY,
        "license": LICENSE,
        "readme": "README.md",
        "rust-version": RUST_VERSION,
    }
    for key, expected in expected_metadata.items():
        actual = package.get(key)
        if actual != expected:
            fail(f"{archive.name} package.{key} is {actual!r}, expected {expected!r}")
    documentation = package.get("documentation")
    if documentation != f"https://docs.rs/{package_name}":
        fail(f"{archive.name} has unexpected documentation URL {documentation!r}")
    if package.get("publish") is False:
        fail(f"{archive.name} is marked publish = false")
    if not files["README.md"].strip():
        fail(f"{archive.name} contains an empty README")

    tracked_readme = repo / PACKAGES[package_name]["path"] / "README.md"
    if files["README.md"] != tracked_readme.read_bytes():
        fail(f"{archive.name} README does not match {tracked_readme.relative_to(repo)}")

    all_dependencies: dict[str, Any] = {}
    for section, dependencies in dependency_tables(manifest):
        for dependency, value in dependencies.items():
            _requirement, _package, path, registry = dependency_details(value)
            if path is not None:
                fail(
                    f"{archive.name} normalized {section}.{dependency} retains local path {path!r}"
                )
            if registry is not None:
                fail(
                    f"{archive.name} normalized {section}.{dependency} uses unexpected registry {registry!r}"
                )
            if dependency.startswith("smolder"):
                all_dependencies[dependency] = value

    expected_dependencies: dict[str, tuple[str, str]] = PACKAGES[package_name][
        "dependencies"
    ]
    if set(all_dependencies) != set(expected_dependencies):
        fail(
            f"{archive.name} internal dependency aliases are {sorted(all_dependencies)}, "
            f"expected {sorted(expected_dependencies)}"
        )
    for alias, (actual_package, expected_requirement) in expected_dependencies.items():
        requirement, renamed_package, path, registry = dependency_details(
            all_dependencies[alias]
        )
        resolved_package = renamed_package or alias
        if requirement != expected_requirement or resolved_package != actual_package:
            fail(
                f"{archive.name} dependency {alias} resolves as {resolved_package} {requirement}; "
                f"expected {actual_package} {expected_requirement}"
            )
        if path is not None or registry is not None:
            fail(f"{archive.name} dependency {alias} is not registry-shaped")

    original_dependencies = original.get("dependencies", {})
    for alias, (actual_package, expected_requirement) in expected_dependencies.items():
        requirement, renamed_package, path, registry = dependency_details(
            original_dependencies.get(alias)
        )
        if (
            requirement != expected_requirement
            or (renamed_package or alias) != actual_package
        ):
            fail(
                f"{archive.name} original manifest has inconsistent dependency {alias}"
            )
        if not isinstance(path, str) or registry is not None:
            fail(
                f"{archive.name} source manifest must pair {alias}'s exact registry requirement with a workspace path"
            )

    vcs_info = json.loads(files[".cargo_vcs_info.json"])
    git_info = vcs_info.get("git", {})
    if git_info.get("sha1") != head:
        fail(
            f"{archive.name} provenance SHA is {git_info.get('sha1')!r}, expected {head}"
        )
    if git_info.get("dirty"):
        fail(f"{archive.name} was built from a dirty tree")
    if vcs_info.get("path_in_vcs") != PACKAGES[package_name]["path"]:
        fail(
            f"{archive.name} has unexpected path_in_vcs {vcs_info.get('path_in_vcs')!r}"
        )

    package_lock = tomllib.loads(files["Cargo.lock"].decode("utf-8"))
    lock_packages = package_lock.get("package", [])
    for _alias, (
        dependency_name,
        expected_requirement,
    ) in expected_dependencies.items():
        matches = [
            entry for entry in lock_packages if entry.get("name") == dependency_name
        ]
        if len(matches) != 1:
            fail(
                f"{archive.name} lockfile does not contain exactly one {dependency_name}"
            )
        entry = matches[0]
        expected_version = expected_requirement.removeprefix("=")
        if entry.get("version") != expected_version:
            fail(
                f"{archive.name} lockfile selected {dependency_name} {entry.get('version')!r}"
            )
        if (
            entry.get("source")
            != "registry+https://github.com/rust-lang/crates.io-index"
        ):
            fail(
                f"{archive.name} lockfile did not resolve {dependency_name} through crates.io"
            )
        expected_checksum = archive_checksums.get(dependency_name)
        if entry.get("checksum") != expected_checksum:
            fail(
                f"{archive.name} lockfile checksum for {dependency_name} is {entry.get('checksum')!r}, "
                f"expected candidate checksum {expected_checksum!r}"
            )

    return {
        "package": package_name,
        "version": version,
        "archive": archive.name,
        "sha256": archive_checksums[package_name],
        "bytes": archive.stat().st_size,
        "file_count": len(files),
        "repository": package["repository"],
        "documentation": package["documentation"],
        "license": package["license"],
        "readme": package["readme"],
        "rust_version": package["rust-version"],
        "internal_dependencies": {
            alias: {"package": target, "requirement": requirement}
            for alias, (target, requirement) in expected_dependencies.items()
        },
    }


def verify_archives(repo: pathlib.Path, candidate: pathlib.Path, version: str) -> None:
    if version != "0.4.0":
        fail(f"this release gate is intentionally pinned to 0.4.0, got {version}")
    if git(repo, "status", "--porcelain", "--untracked-files=all"):
        fail("repository must be clean so archive provenance is unambiguous")
    head = git(repo, "rev-parse", "HEAD")
    archive_dir = candidate / "archives"
    expected_archives = {
        package: archive_dir / f"{package}-{version}.crate" for package in PUBLISH_ORDER
    }
    for archive in expected_archives.values():
        if not archive.is_file():
            fail(f"missing candidate archive {archive}")
    excluded = list(archive_dir.glob("smolder-psexecsvc-*.crate"))
    if excluded:
        fail("smolder-psexecsvc must not be present in the 0.4.0 candidate archive set")
    unexpected = sorted(
        path.name
        for path in archive_dir.glob("*.crate")
        if path not in expected_archives.values()
    )
    if unexpected:
        fail(
            f"candidate directory contains unexpected archives: {', '.join(unexpected)}"
        )

    archive_checksums = {
        package: sha256_file(archive) for package, archive in expected_archives.items()
    }
    records = [
        inspect_package(
            repo, expected_archives[package], package, version, archive_checksums, head
        )
        for package in PUBLISH_ORDER
    ]

    evidence = {
        "schema": 1,
        "release": version,
        "source_commit": head,
        "source_repository": REPOSITORY,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "publish_order": PUBLISH_ORDER,
        "excluded_packages": {"smolder-psexecsvc": "0.3.0"},
        "archives": records,
        "checks": {
            "safe_archive_members": "pass",
            "normalized_manifests_have_no_path_dependencies": "pass",
            "internal_dependencies_are_exact": "pass",
            "metadata_and_readmes_match_source": "pass",
            "vcs_provenance_is_clean_head": "pass",
            "high_confidence_secret_scan": "pass",
            "archive_lockfiles_resolve_candidate_checksums": "pass",
        },
    }
    candidate.mkdir(parents=True, exist_ok=True)
    (candidate / "evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (candidate / "SHA256SUMS").open("w", encoding="utf-8") as output:
        for package in PUBLISH_ORDER:
            output.write(
                f"{archive_checksums[package]}  archives/{expected_archives[package].name}\n"
            )

    print(f"release candidate source: {head}")
    print("publish order: " + " -> ".join(PUBLISH_ORDER))
    for record in records:
        print(
            f"{record['sha256']}  {record['archive']} ({record['bytes']} bytes, {record['file_count']} files)"
        )
    print(f"archive evidence: {candidate / 'evidence.json'}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    install = subparsers.add_parser(
        "install", help="install a .crate in a Cargo directory source"
    )
    install.add_argument("--archive", required=True, type=pathlib.Path)
    install.add_argument("--registry", required=True, type=pathlib.Path)

    verify = subparsers.add_parser(
        "verify", help="inspect the complete release archive set"
    )
    verify.add_argument("--repo", required=True, type=pathlib.Path)
    verify.add_argument("--candidate", required=True, type=pathlib.Path)
    verify.add_argument("--version", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "install":
        destination = install_archive(args.archive.resolve(), args.registry.resolve())
        print(destination)
    elif args.command == "verify":
        verify_archives(args.repo.resolve(), args.candidate.resolve(), args.version)
    else:
        fail(f"unknown command {args.command}")


if __name__ == "__main__":
    main()
