#!/usr/bin/env python3
"""Archive a completed fixed-track attempt and prepare a fresh campaign."""
import argparse
import json
import subprocess
from datetime import datetime, timezone

from pbfuzz_fixed_campaign import RESULTS, ROOT, fixed_rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bug_id")
    args = parser.parse_args()
    row = fixed_rows().get(args.bug_id)
    if row is None:
        parser.error("bug ID is outside the frozen 60")
    work = RESULTS / "fixed" / args.bug_id
    if not (work / "run.json").is_file():
        parser.error("run.json absent; wait for the run to finish")
    project, _ = row
    repo = ROOT / "magma/work/idfuzz" / args.bug_id / "target/repo"
    status = repo / ".pbfuzz" / f"fixed-{args.bug_id.lower()}"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = RESULTS / "prior-attempts" / args.bug_id / stamp
    archive.mkdir(parents=True)
    if status.is_symlink():
        status.unlink()
    elif status.exists():
        status.rename(archive / "engine-output")
    campaign = repo / ".pbfuzz/campaigns" / f"{args.bug_id}.fixed.campaign.yaml"
    if campaign.exists():
        campaign.rename(archive / "campaign.yaml")
    work.rename(archive / "evidence")
    isolated = RESULTS / "isolated" / args.bug_id
    if isolated.exists():
        isolated.rename(archive / "isolated")
    subprocess.run(["python3", str(ROOT / "scripts/pbfuzz_fixed_campaign.py"), args.bug_id],
                   cwd=ROOT, check=True)
    print(json.dumps({"bug_id": args.bug_id, "archived_to": str(archive),
                      "isolated_status": str(status)}, sort_keys=True))


if __name__ == "__main__":
    main()
