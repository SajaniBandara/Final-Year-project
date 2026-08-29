"""Task-8 verification evidence: the equation audit and the functional check.

Answers the question a viva asks that no metric chart can: *does the code
actually implement the thesis?* ``scripts/audit_equations.py`` walks every
``eq:``/``alg:`` label in ``docs/main.tex`` and either points at the implementing
symbol, confirms the parameter plumbing, or declares it paper-only -- plus a
coverage self-check that fails if the paper grows a label the audit table has
not caught up with.

This module parses that script's output into structure. It does not soften the
result: the audit currently **fails**, and a tab that showed only the pass count
would be worse than no tab at all.

Running vs reading
------------------
The audit takes ~14 s, too slow for a page load, so the parsed view reads a
stored log at the path ``FUNCTIONAL_VERIFICATION_GUIDE.md`` §4 specifies.
:func:`run_audit` regenerates it on demand -- worth having in a demo, where
re-running the audit live is more convincing than showing a file. It invokes a
fixed script with fixed arguments and takes no caller input.

``functional_verification.py`` is the behavioural half and needs a finished
simulation's artefacts, so it is reported as available-or-not with the command
to produce it rather than run from here.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .catalog import REPO_ROOT

VERIFICATION_DIR = REPO_ROOT / "docs" / "task8_verification"
AUDIT_LOG = VERIFICATION_DIR / "equation_audit.log"
FUNCTIONAL_LOG = VERIFICATION_DIR / "functional_verification.log"

AUDIT_SCRIPT = REPO_ROOT / "scripts" / "audit_equations.py"
FUNCTIONAL_SCRIPT = REPO_ROOT / "scripts" / "functional_verification.py"

#: Generous: the audit walks the whole source tree plus main.tex (~14 s here).
AUDIT_TIMEOUT_S = 300

_SECTION_RE = re.compile(r"^SECTION\s+(?P<id>\S+)\.\s+(?P<title>.+?)\s*$")
_CHECK_RE = re.compile(r"^\s{2}\[(?P<status>PASS|FAIL|INFO)\]\s+(?P<label>\S+)\s*(?P<text>.*)$")
_DETAIL_RE = re.compile(r"^\s{7,}(?P<detail>\S.*)$")
_RESULT_RE = re.compile(r"(?P<pass>\d+)\s+PASS,\s*(?P<fail>\d+)\s+FAIL,\s*(?P<info>\d+)\s+INFO")
_SUMMARY_FIELD_RE = re.compile(r"^\s{2}(?P<key>[a-z][a-z \-]+?)\s*:\s*(?P<value>.+?)\s*$")


@dataclass
class Check:
    """One audited equation or algorithm."""

    status: str
    label: str
    text: str
    details: list[str]
    section: str

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "label": self.label,
            "text": self.text,
            "details": self.details,
            "section": self.section,
        }


def parse_audit(text: str) -> dict[str, object]:
    """Parse ``audit_equations.py`` output into sections, checks and a summary."""
    sections: list[dict[str, object]] = []
    checks: list[Check] = []
    summary: dict[str, str] = {}
    current_section = "(preamble)"
    current: Check | None = None
    in_summary = False

    for line in text.splitlines():
        section_match = _SECTION_RE.match(line)
        if section_match:
            current_section = f"{section_match['id']}. {section_match['title']}"
            in_summary = section_match["id"].upper().startswith("SUMMARY")
            sections.append({"id": section_match["id"], "title": section_match["title"]})
            current = None
            continue

        if line.startswith("AUDIT SUMMARY"):
            in_summary = True
            current = None
            continue

        check_match = _CHECK_RE.match(line)
        if check_match:
            current = Check(
                status=check_match["status"],
                label=check_match["label"],
                text=check_match["text"].strip(),
                details=[],
                section=current_section,
            )
            checks.append(current)
            continue

        detail_match = _DETAIL_RE.match(line)
        if detail_match and current is not None:
            current.details.append(detail_match["detail"].strip())
            continue

        if in_summary:
            field = _SUMMARY_FIELD_RE.match(line)
            if field:
                summary[field["key"].strip()] = field["value"].strip()

        current = None if line.strip().startswith("=") else current

    counts = {"PASS": 0, "FAIL": 0, "INFO": 0}
    for check in checks:
        counts[check.status] += 1

    # The script's own tally is authoritative. Cross-check our parse against it
    # on PASS and FAIL only: the script's INFO count is "paper-only, by
    # declaration" and deliberately excludes the coverage section's two
    # stale-entry INFO lines, so those two counts differ by design and comparing
    # them would raise a false alarm on every healthy run.
    reported = None
    result_line = summary.get("result", "")
    match = _RESULT_RE.search(result_line)
    if match:
        reported = {
            "PASS": int(match["pass"]),
            "FAIL": int(match["fail"]),
            "INFO": int(match["info"]),
        }

    return {
        "sections": sections,
        "checks": [c.to_dict() for c in checks],
        "failures": [c.to_dict() for c in checks if c.status == "FAIL"],
        "counts_parsed": counts,
        "counts_reported": reported,
        "counts_agree": reported is None or (
            reported["PASS"] == counts["PASS"] and reported["FAIL"] == counts["FAIL"]
        ),
        "summary": summary,
        "passed": bool(reported and reported["FAIL"] == 0),
    }


def read_audit() -> dict[str, object]:
    """Parsed audit from the stored log, or a not-available payload."""
    if not AUDIT_LOG.is_file():
        return {
            "available": False,
            "log_path": str(AUDIT_LOG),
            "command": (
                f"python scripts/audit_equations.py --self-test --no-color "
                f"> docs/task8_verification/equation_audit.log"
            ),
        }
    text = AUDIT_LOG.read_text(encoding="utf-8", errors="replace")
    parsed = parse_audit(text)
    parsed["available"] = True
    parsed["log_path"] = str(AUDIT_LOG)
    parsed["modified"] = AUDIT_LOG.stat().st_mtime
    return parsed


def run_audit(self_test: bool = False) -> dict[str, object]:
    """Re-run the audit and store its log, then return the parsed result.

    Args:
        self_test: Also run the negative control (Section S), which erases each
            equation's symbol from the source index and confirms the check flips
            to FAIL -- proof that no check passes vacuously. Slower.

    Raises:
        FileNotFoundError: if the audit script is missing.
        RuntimeError: if the script cannot be executed.
    """
    if not AUDIT_SCRIPT.is_file():
        raise FileNotFoundError(f"audit script not found: {AUDIT_SCRIPT}")

    command = [sys.executable, str(AUDIT_SCRIPT), "--no-color"]
    if self_test:
        command.append("--self-test")

    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=AUDIT_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"audit timed out after {AUDIT_TIMEOUT_S}s") from exc

    output = completed.stdout or completed.stderr
    VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_LOG.write_text(output, encoding="utf-8")

    parsed = parse_audit(output)
    parsed["available"] = True
    parsed["log_path"] = str(AUDIT_LOG)
    # The script exits non-zero only under --strict, so its own tally decides.
    parsed["exit_code"] = completed.returncode
    return parsed


def read_functional() -> dict[str, object]:
    """Status of the behavioural verification log.

    Not run from here: it is a *post-run* checker over a finished simulation's
    CSVs, so producing it needs a sweep first.
    """
    if not FUNCTIONAL_LOG.is_file():
        return {
            "available": False,
            "log_path": str(FUNCTIONAL_LOG),
            "command": (
                "python scripts/functional_verification.py --no-color "
                "> docs/task8_verification/functional_verification.log"
            ),
            "note": (
                "Behavioural verification reads the CSVs a finished run produced, "
                "so it needs a sweep before it can be generated."
            ),
        }
    text = FUNCTIONAL_LOG.read_text(encoding="utf-8", errors="replace")
    counts = {
        status: len(re.findall(rf"\[{status}\]", text)) for status in ("PASS", "FAIL", "WARN")
    }
    return {
        "available": True,
        "log_path": str(FUNCTIONAL_LOG),
        "counts": counts,
        "modified": FUNCTIONAL_LOG.stat().st_mtime,
        "passed": counts["FAIL"] == 0,
    }


def panel() -> dict[str, object]:
    """Everything the Verification tab needs."""
    return {
        "audit": read_audit(),
        "functional": read_functional(),
        "script_present": AUDIT_SCRIPT.is_file(),
        "functional_script_present": FUNCTIONAL_SCRIPT.is_file(),
    }
