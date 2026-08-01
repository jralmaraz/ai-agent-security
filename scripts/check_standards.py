#!/usr/bin/env python3
"""
Daily standards tracker for the WIMSE Identity Fabric PoC.

Reads standards-baseline.json, queries the IETF Datatracker API for each
tracked draft, and reports revision changes.  When updates are found it:
  1. Writes the updated baseline back to disk (to be committed by the workflow).
  2. Writes a GitHub issue body to /tmp/standards_issue_body.md.
  3. Sets GITHUB_OUTPUT variables: updates_found, issue_title.

Standards with api_url=null (e.g. OpenID Foundation specs) are skipped by the
API check and flagged for manual review only.

Usage:
    python3 scripts/check_standards.py          # local test
    python3 scripts/check_standards.py          # in GitHub Actions
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

BASELINE_FILE   = "standards-baseline.json"
ISSUE_BODY_FILE = "/tmp/standards_issue_body.md"
GITHUB_OUTPUT   = os.environ.get("GITHUB_OUTPUT", os.devnull)


def fetch_ietf(draft_name: str) -> dict | None:
    url = f"https://datatracker.ietf.org/api/v1/doc/document/{draft_name}/"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"    HTTP {e.code}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"    {e}", file=sys.stderr)
        return None


def main() -> None:
    with open(BASELINE_FILE) as f:
        baseline = json.load(f)

    updates: list[dict] = []

    print(f"Checking {len(baseline['standards'])} standard(s)…\n")

    for std in baseline["standards"]:
        name    = std["id"]
        api_url = std.get("api_url")

        if not api_url:
            print(f"  SKIP  {name:<55} (no API — manual tracking)")
            continue

        print(f"  CHECK {name:<55}", end="", flush=True)
        data = fetch_ietf(name)
        if data is None:
            print(" FETCH FAILED")
            continue

        new_rev   = str(data.get("rev") or "").strip()
        known_rev = str(std.get("last_known_rev") or "").strip()

        if new_rev and new_rev != known_rev:
            print(f" UPDATED  -{known_rev} → -{new_rev}")
            updates.append({
                **std,
                "old_rev":      known_rev,
                "new_rev":      new_rev,
                "api_title":    data.get("title", name),
                "abstract":     (data.get("abstract") or "")[:500],
                "last_updated": (data.get("time") or "")[:10],
            })
            std["last_known_rev"] = new_rev
        else:
            print(f" OK       rev={new_rev or known_rev}")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    baseline["last_checked"] = today

    # ── No updates ────────────────────────────────────────────────────────
    if not updates:
        print("\nAll standards are at their last-known revision. Nothing to do.")
        with open(GITHUB_OUTPUT, "a") as f:
            f.write("updates_found=false\n")
        return

    # ── Persist updated baseline ──────────────────────────────────────────
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
        f.write("\n")

    # ── Build GitHub issue body ───────────────────────────────────────────
    repo    = os.environ.get("GITHUB_REPOSITORY", "this repo")
    run_id  = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"https://github.com/{repo}/actions/runs/{run_id}" if run_id else \
              f"https://github.com/{repo}/actions"

    body: list[str] = [
        f"## {len(updates)} Standard(s) Updated — {today}\n",
        f"_Detected by the [standards-tracker workflow]({run_url})._  "
        f"Baseline file: [`standards-baseline.json`](standards-baseline.json)\n",
    ]

    for u in updates:
        impl_rev = str(u.get("implemented_rev") or u["old_rev"]).strip()
        body += [
            "---",
            f"### {u['label']}",
            f"`{u['id']}`",
            "",
            "| | |",
            "|---|---|",
            f"| **New revision** | `{u['id']}-{u['new_rev'].zfill(2)}` |",
            f"| **Previously tracked** | `{u['id']}-{u['old_rev'].zfill(2)}` |",
            f"| **Implemented in PoC** | `{u['id']}-{impl_rev.zfill(2)}` |",
            f"| **Last updated** | {u['last_updated']} |",
            f"| **Datatracker** | {u['datatracker_url']} |",
            "",
        ]
        if u.get("abstract"):
            body += [f"> {u['abstract'][:400]}…", ""]
        if u.get("impact"):
            body += [f"**PoC impact:** {u['impact']}", ""]
        if u.get("used_in"):
            pkgs = ", ".join(f"`{p}`" for p in u["used_in"])
            body += [f"**Affected packages:** {pkgs}", ""]
        body += [
            "**Action checklist:**",
            "- [ ] Read the diff on IETF Datatracker (compare revisions link)",
            "- [ ] Check for changed `typ` values, claim names, or header names",
            "- [ ] Update Go implementation if there are breaking changes",
            "- [ ] Update the demo HTML version numbers",
            f"- [ ] Set `implemented_rev` to `\"{u['new_rev']}\"` in `{BASELINE_FILE}` when done",
            "",
        ]

    with open(ISSUE_BODY_FILE, "w") as f:
        f.write("\n".join(body))

    draft_list  = ", ".join(f"{u['id']}-{u['new_rev'].zfill(2)}" for u in updates)
    issue_title = f"[Standards Update] {len(updates)} draft(s) updated: {draft_list}"

    with open(GITHUB_OUTPUT, "a") as f:
        f.write("updates_found=true\n")
        f.write(f"issue_title={issue_title[:200]}\n")   # GitHub output is single-line

    print(f"\n{len(updates)} update(s) found — issue will be created.")


if __name__ == "__main__":
    main()
