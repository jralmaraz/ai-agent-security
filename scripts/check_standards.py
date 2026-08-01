#!/usr/bin/env python3
"""
Daily standards tracker for the WIMSE Identity Fabric PoC.

Three check methods:
  1. IETF Datatracker API  — per-draft REST API  (api_url set on standard)
  2. OpenID Foundation RSS  — keyword-filtered RSS (rss_url set on standard)
  3. WG / org Atom feeds    — discovery of new drafts  (wg_feeds section)

When updates are found it:
  1. Updates standards-baseline.json (committed by the workflow).
  2. Writes a GitHub issue body to /tmp/standards_issue_body.md.
  3. Sets GITHUB_OUTPUT: updates_found, issue_title.

Usage:
    python3 scripts/check_standards.py          # local test
    python3 scripts/check_standards.py          # in GitHub Actions
"""

import json
import os
import re
import sys
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

BASELINE_FILE   = "standards-baseline.json"
ISSUE_BODY_FILE = "/tmp/standards_issue_body.md"
GITHUB_OUTPUT   = os.environ.get("GITHUB_OUTPUT", os.devnull)
NS_ATOM         = "http://www.w3.org/2005/Atom"


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def http_get(url: str, accept: str = "*/*") -> bytes | None:
    try:
        req = urllib.request.Request(
            url,
            headers={"Accept": accept, "User-Agent": "wimse-standards-tracker/1.0"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        print(f"    HTTP {e.code}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"    {e}", file=sys.stderr)
        return None


def parse_xml(raw: bytes, label: str) -> ET.Element | None:
    try:
        return ET.fromstring(raw)
    except ET.ParseError as e:
        print(f"    XML parse error ({label}): {e}", file=sys.stderr)
        return None


# ── Check method 1: IETF Datatracker REST API ─────────────────────────────────

def fetch_ietf(draft_name: str) -> dict | None:
    raw = http_get(
        f"https://datatracker.ietf.org/api/v1/doc/document/{draft_name}/",
        accept="application/json",
    )
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"    JSON error: {e}", file=sys.stderr)
        return None


# ── Check method 2: RSS / Atom keyword feed ───────────────────────────────────

def check_rss_feed(
    rss_url: str, keywords: list[str], last_guid: str | None
) -> tuple[list[dict], str | None]:
    """
    Parse an RSS 2.0 or Atom feed, filter items whose title+link contain any keyword.
    Returns (new_items_since_last_guid, updated_last_guid).

    First-run semantics (last_guid is None): record baseline GUID without alerting.
    """
    raw = http_get(rss_url)
    if raw is None:
        return [], last_guid

    root = parse_xml(raw, rss_url)
    if root is None:
        return [], last_guid

    # Prefer RSS 2.0 <item>; fall back to Atom <entry>
    items_xml = root.findall(".//item") or root.findall(f".//{{{NS_ATOM}}}entry")
    kw_lower  = [k.lower() for k in keywords]
    matched: list[dict] = []

    for item in items_xml:
        def _t(tag: str, ns: str = "") -> str:
            ns_tag = f"{{{ns}}}{tag}" if ns else tag
            el = item.find(ns_tag)
            if el is None:
                return ""
            return (el.text or el.get("href", "")).strip()

        title = _t("title")   or _t("title", NS_ATOM)
        link  = _t("link")    or _t("link",  NS_ATOM)
        guid  = _t("guid")    or _t("id",    NS_ATOM) or link
        date  = (_t("pubDate") or _t("updated", NS_ATOM) or _t("published", NS_ATOM))[:10]

        # Atom <link> href is an attribute, not text
        if not link:
            el = item.find(f"{{{NS_ATOM}}}link")
            if el is not None:
                link = el.get("href", "")
            if not guid:
                guid = link

        if any(kw in (title + " " + link).lower() for kw in kw_lower):
            matched.append({"title": title, "link": link, "guid": guid, "date": date})

    if not matched:
        return [], last_guid

    latest_guid = matched[0]["guid"]  # RSS is newest-first

    if last_guid is None:
        # Initialise baseline silently
        return [], latest_guid

    if latest_guid == last_guid:
        return [], last_guid

    new_items: list[dict] = []
    for item in matched:
        if item["guid"] == last_guid:
            break
        new_items.append(item)

    return new_items, latest_guid


# ── Check method 3: IETF WG Atom feed — discover new drafts ──────────────────

def check_wg_atom_feed(feed_url: str, known_ids: set[str]) -> list[dict]:
    """
    Fetch an IETF WG Atom feed and return entries for document IDs not in known_ids.
    De-duplicates within a single run (a doc appears once per revision upload).
    """
    raw = http_get(feed_url)
    if raw is None:
        return []

    root = parse_xml(raw, feed_url)
    if root is None:
        return []

    seen: set[str] = set()
    discoveries: list[dict] = []

    for entry in root.findall(f"{{{NS_ATOM}}}entry"):
        link_el    = entry.find(f"{{{NS_ATOM}}}link")
        title_el   = entry.find(f"{{{NS_ATOM}}}title")
        updated_el = entry.find(f"{{{NS_ATOM}}}updated")

        link    = link_el.get("href", "") if link_el is not None else ""
        title   = (title_el.text or "").strip() if title_el is not None else ""
        updated = (updated_el.text or "")[:10] if updated_el is not None else ""

        m = re.search(r"/doc/(draft-[a-z0-9-]+)/", link)
        if not m:
            continue
        doc_id = m.group(1)

        if doc_id in known_ids or doc_id in seen:
            continue
        seen.add(doc_id)
        discoveries.append({"id": doc_id, "title": title, "link": link, "date": updated})

    return discoveries


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    with open(BASELINE_FILE) as f:
        baseline = json.load(f)

    updates: list[dict] = []      # changed revisions / new RSS posts
    discoveries: list[dict] = []  # new drafts found via WG feeds
    known_ids = {s["id"] for s in baseline["standards"]}

    print(f"Checking {len(baseline['standards'])} tracked standard(s)…\n")

    # ── Per-standard checks ───────────────────────────────────────────────────
    for std in baseline["standards"]:
        name    = std["id"]
        api_url = std.get("api_url")
        rss_url = std.get("rss_url")

        if api_url:
            print(f"  IETF  {name:<58}", end="", flush=True)
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
                    "check_method": "ietf-api",
                    "old_rev":      known_rev,
                    "new_rev":      new_rev,
                    "api_title":    data.get("title", name),
                    "abstract":     (data.get("abstract") or "")[:500],
                    "last_updated": (data.get("time") or "")[:10],
                })
                std["last_known_rev"] = new_rev
            else:
                print(f" OK       rev={new_rev or known_rev}")

        elif rss_url:
            keywords  = std.get("rss_keywords", [std.get("short", name).lower()])
            last_guid = std.get("last_rss_guid")
            print(f"  RSS   {name:<58}", end="", flush=True)
            new_items, latest_guid = check_rss_feed(rss_url, keywords, last_guid)
            std["last_rss_guid"] = latest_guid
            if new_items:
                print(f" ACTIVITY  {len(new_items)} new post(s)")
                updates.append({
                    **std,
                    "check_method": "rss",
                    "rss_items":    new_items,
                    "last_updated": new_items[0]["date"],
                })
            else:
                if last_guid is None:
                    pass  # already printed "(first run)" inside check_rss_feed
                else:
                    print(" OK")

        else:
            print(f"  SKIP  {name:<58} (manual tracking)")

    # ── WG / org feed discovery ───────────────────────────────────────────────
    wg_feeds = baseline.get("wg_feeds", [])
    if wg_feeds:
        print(f"\nChecking {len(wg_feeds)} WG / org feed(s)…\n")

    for wf in wg_feeds:
        feed_type = wf.get("type", "ietf-wg")
        print(f"  FEED  {wf['name']:<58}", end="", flush=True)

        if feed_type == "ietf-wg":
            found = check_wg_atom_feed(wf["feed_url"], known_ids)
            if found:
                print(f" {len(found)} new draft(s) discovered")
                for d in found:
                    print(f"        ↳ {d['id']}")
                discoveries.extend(
                    [{**d, "wg_name": wf["name"], "feed_url": wf["feed_url"]}
                     for d in found]
                )
            else:
                print(" OK — no unknown drafts")

        elif feed_type == "rss":
            keywords  = wf.get("keywords", [])
            last_guid = wf.get("last_guid")
            new_items, latest_guid = check_rss_feed(wf["feed_url"], keywords, last_guid)
            wf["last_guid"] = latest_guid
            if new_items:
                print(f" {len(new_items)} new post(s)")
                discoveries.extend([{
                    "id":       item["link"],
                    "title":    item["title"],
                    "link":     item["link"],
                    "date":     item["date"],
                    "wg_name":  wf["name"],
                    "feed_url": wf["feed_url"],
                    "is_rss":   True,
                } for item in new_items])
            else:
                if last_guid is None:
                    pass  # first run, silent
                else:
                    print(" OK")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    baseline["last_checked"] = today

    # ── Nothing to report ─────────────────────────────────────────────────────
    if not updates and not discoveries:
        print("\nAll standards current. No new drafts discovered. Nothing to do.")
        # Still write baseline to persist any last_rss_guid updates
        with open(BASELINE_FILE, "w") as f:
            json.dump(baseline, f, indent=2)
            f.write("\n")
        with open(GITHUB_OUTPUT, "a") as f:
            f.write("updates_found=false\n")
        return

    # ── Persist updated baseline ──────────────────────────────────────────────
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
        f.write("\n")

    # ── Build GitHub issue body ───────────────────────────────────────────────
    repo    = os.environ.get("GITHUB_REPOSITORY", "this repo")
    run_id  = os.environ.get("GITHUB_RUN_ID", "")
    run_url = (
        f"https://github.com/{repo}/actions/runs/{run_id}"
        if run_id else f"https://github.com/{repo}/actions"
    )

    body: list[str] = [
        f"## Standards Activity — {today}\n",
        f"_Detected by the [standards-tracker workflow]({run_url})._  "
        f"Baseline: [`standards-baseline.json`]"
        f"(https://github.com/{repo}/blob/main/standards-baseline.json)\n",
    ]

    api_updates = [u for u in updates if u.get("check_method") == "ietf-api"]
    rss_updates = [u for u in updates if u.get("check_method") == "rss"]

    # IETF draft revision updates
    if api_updates:
        body.append(f"\n### {len(api_updates)} IETF Draft Revision(s)\n")
        for u in api_updates:
            impl_rev = str(u.get("implemented_rev") or u["old_rev"]).strip()
            body += [
                "---",
                f"#### {u['label']}",
                f"`{u['id']}`\n",
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
                body += [
                    "**Affected packages:** "
                    + ", ".join(f"`{p}`" for p in u["used_in"]),
                    "",
                ]
            body += [
                "**Action checklist:**",
                "- [ ] Read the diff on IETF Datatracker (compare revisions link)",
                "- [ ] Check for changed `typ` values, claim names, or header names",
                "- [ ] Update Go implementation if there are breaking changes",
                "- [ ] Update the demo HTML version numbers",
                f"- [ ] Set `implemented_rev` to `\"{u['new_rev']}\"` in `{BASELINE_FILE}` when done",
                "",
            ]

    # RSS / OIDF updates
    if rss_updates:
        body.append(f"\n### {len(rss_updates)} RSS / OpenID Foundation Update(s)\n")
        for u in rss_updates:
            body += ["---", f"#### {u['label']}", ""]
            for item in u.get("rss_items", [])[:5]:
                body.append(f"- [{item['title']}]({item['link']}) — {item['date']}")
            body += [
                "",
                "**Action checklist:**",
                "- [ ] Read the post(s) above and confirm if spec content changed",
                f"- [ ] Visit {u['datatracker_url']} to confirm version",
                "- [ ] Update Go implementation if there are breaking changes",
                f"- [ ] Update `last_known_rev` and `implemented_rev` in `{BASELINE_FILE}` when done",
                "",
            ]

    # WG discovery (new drafts + RSS org posts)
    if discoveries:
        new_drafts = [d for d in discoveries if not d.get("is_rss")]
        rss_posts  = [d for d in discoveries if d.get("is_rss")]

        if new_drafts:
            body.append(f"\n### {len(new_drafts)} New Draft(s) Discovered in WG Feed(s)\n")
            body.append("_Not yet in the tracking baseline. Review and add if relevant._\n")
            for d in new_drafts:
                body += [
                    "---",
                    f"#### `{d['id']}`",
                    f"**Title:** {d['title']}  ",
                    f"**WG:** {d['wg_name']}  ",
                    f"**Datatracker:** {d['link']}  ",
                    f"**First seen:** {d['date']}  ",
                    "",
                    "**Action checklist:**",
                    f"- [ ] Review the draft at {d['link']}",
                    "- [ ] Decide if relevant to the PoC implementation",
                    f"- [ ] If yes: add entry to `{BASELINE_FILE}` with `api_url` set and implement required changes",
                    "",
                ]

        if rss_posts:
            body.append(f"\n### {len(rss_posts)} New Post(s) from Org RSS Feed(s)\n")
            for d in rss_posts:
                body.append(f"- **{d['wg_name']}**: [{d['title']}]({d['link']}) — {d['date']}")
            body.append("")

    with open(ISSUE_BODY_FILE, "w") as f:
        f.write("\n".join(body))

    parts: list[str] = []
    if api_updates:
        parts.append(f"{len(api_updates)} revision(s)")
    if rss_updates:
        parts.append(f"{len(rss_updates)} RSS update(s)")
    if discoveries:
        parts.append(f"{len(discoveries)} new discovery(ies)")
    issue_title = f"[Standards Tracker] {', '.join(parts)}"

    with open(GITHUB_OUTPUT, "a") as f:
        f.write("updates_found=true\n")
        f.write(f"issue_title={issue_title[:200]}\n")

    print(f"\n{len(updates)} update(s), {len(discoveries)} discovery(ies) — issue will be created.")


if __name__ == "__main__":
    main()
