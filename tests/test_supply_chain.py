"""Supply-chain policy for workflows, Dockerfiles and Dependabot (R-15, R-16, R-17)."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
DOCKERFILES = sorted(p for p in ROOT.rglob("Dockerfile*") if ".git" not in p.parts)
DEPENDABOT = (ROOT / ".github" / "dependabot.yml").read_text()


def ids(paths):
    return [str(p.relative_to(ROOT)) for p in paths]


@pytest.mark.parametrize("path", WORKFLOWS, ids=ids(WORKFLOWS))
def test_actions_pinned_to_full_sha_with_tag_comment(path):
    for line in path.read_text().splitlines():
        m = re.search(r"uses:\s*(\S+)", line)
        if not m or m.group(1).startswith("./"):
            continue
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", m.group(1)), f"unpinned: {line.strip()}"
        assert re.search(r"#\s*v?\d", line), f"missing tag comment: {line.strip()}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=ids(WORKFLOWS))
def test_top_level_token_is_read_only(path):
    text = path.read_text()
    top = re.search(r"^permissions:\s*\n((?:[ \t]+.*\n)+)", text, re.M)
    assert top, "no top-level permissions block"
    grants = re.findall(r"^\s+([\w-]+):\s*(\w+)", top.group(1), re.M)
    assert all(level in ("read", "none") for _, level in grants), grants


@pytest.mark.parametrize("path", WORKFLOWS, ids=ids(WORKFLOWS))
def test_checkout_never_persists_credentials(path):
    steps = re.split(r"\n\s*- ", path.read_text())
    for step in steps:
        if "actions/checkout@" in step:
            assert re.search(r"persist-credentials:\s*false", step), "checkout keeps the token in .git/config"


@pytest.mark.parametrize("path", WORKFLOWS, ids=ids(WORKFLOWS))
def test_pull_request_target_never_checks_out_pull_request_code(path):
    # pull_request_target runs with secrets; it is safe only when no PR code is checked out
    # or executed, and only for same-repository pull requests (Lab 4 rule, R-16).
    text = path.read_text()
    if "pull_request_target" not in text:
        return
    assert "pull_request.head.sha" not in text and "pull_request.head.ref" not in text
    assert "github.head_ref" not in text and "refs/pull/" not in text
    assert "ref: ${{ github.event.pull_request.base.sha }}" in text
    assert "head.repo.full_name == github.repository" in text


@pytest.mark.parametrize("path", WORKFLOWS, ids=ids(WORKFLOWS))
def test_no_expressions_inside_run_scripts(path):
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"(\s*)(- )?run:\s*(.*)", line)
        if not m:
            continue
        indent = len(m.group(1)) + (2 if m.group(2) else 0)
        block = [m.group(3)]
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            block.append(nxt)
        assert "${{" not in "\n".join(block), f"expression in run script near line {i + 1}"


@pytest.mark.parametrize("path", DOCKERFILES, ids=ids(DOCKERFILES))
def test_dockerfile_base_images_pinned_by_digest(path):
    froms = [line.split()[1] for line in path.read_text().splitlines()
             if line.strip().upper().startswith("FROM ")]
    assert froms, "no FROM line"
    for image in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"unpinned base image: {image}"


@pytest.mark.parametrize("path", DOCKERFILES, ids=ids(DOCKERFILES))
def test_dockerfile_drops_root(path):
    users = [line.split()[1] for line in path.read_text().splitlines() if line.startswith("USER ")]
    assert users and users[-1] not in ("root", "0"), "image runs as root"


def test_ci_runs_the_image_it_scans():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    scan = ci.split("\n  scan:", 1)[1].split("\n  release:", 1)[0]
    assert "docker run --rm hunt-toolkit:ci" in scan, "scan job never starts the image it ships"


def test_every_dependabot_entry_has_a_cooldown():
    entries = DEPENDABOT.split("- package-ecosystem:")[1:]
    assert entries
    for entry in entries:
        assert re.search(r"cooldown:\s*\n\s+default-days:\s*[1-9]", entry), entry.split()[0]
