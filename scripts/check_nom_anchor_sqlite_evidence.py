#!/usr/bin/env python3
"""Review original finite SQLite evidence without repair, import or native execution."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import nom_anchor_sqlite_review as review  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--allow-incomplete-for-retention", action="store_true")
    parser.add_argument("--expect-platform", choices=("darwin", "linux"))
    args = parser.parse_args()
    try:
        if not __debug__:
            raise review.ReviewRefused("unoptimized qualification runtime required")
        result = review.review(args.evidence_directory, ROOT,
            allow_incomplete=args.allow_incomplete_for_retention, platform=args.expect_platform)
    except (ValueError, OSError, TypeError, KeyError, RecursionError, UnicodeError) as error:
        print(json.dumps(dict(schema=review.SCHEMA, disposition="REFUSED_NOT_QUALIFIED",
            error_class=type(error).__name__, application="NO-GO", core="NO-GO", recovery_action="NONE"), sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
