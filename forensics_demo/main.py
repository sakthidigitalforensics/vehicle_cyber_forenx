#!/usr/bin/env python3
"""
CLI entrypoint for the extraction engine prototype.

Usage:
    python3 main.py <evidence_folder> [--out output/findings.json]

Runs entirely offline - no network calls are made anywhere in this pipeline.
"""

import argparse
import json
import sys
from extractors.pipeline import run_pipeline


def main():
    parser = argparse.ArgumentParser(description="Cyber forensic evidence extraction engine (offline prototype)")
    parser.add_argument("evidence_dir", help="Folder containing evidence files")
    parser.add_argument("--out", default="output/findings.json", help="Where to write the findings JSON")
    args = parser.parse_args()

    findings, skipped, files_processed, events = run_pipeline(args.evidence_dir)

    result = {
        "summary": {
            "files_processed": files_processed,
            "files_skipped": len(skipped),
            "skipped_files": skipped,
            "total_findings": len(findings),
            "findings_by_type": {},
        },
        "findings": [f.to_dict() for f in findings],
    }
    for f in findings:
        result["summary"]["findings_by_type"][f.type] = result["summary"]["findings_by_type"].get(f.type, 0) + 1

    with open(args.out, "w") as out:
        json.dump(result, out, indent=2)

    print(f"Processed {files_processed} file(s), skipped {len(skipped)}.")
    print(f"Classified {len(events)} timeline events.")
    print(f"Extracted {len(findings)} deduplicated findings.")
    print("By type:")
    for t, c in sorted(result["summary"]["findings_by_type"].items(), key=lambda x: -x[1]):
        print(f"  {t:14s} {c}")
    print(f"\nFull output written to {args.out}")
    if skipped:
        print(f"\nSkipped/unsupported files: {skipped}")


if __name__ == "__main__":
    sys.exit(main())
