
#!/usr/bin/env python3
"""
Photo Organizer - Standalone Script
-----------------------------------
Organize images into Year/Month folders based on EXIF 'DateTimeOriginal' when available,
otherwise file modified time. Supports dry-run, copy/move, recursive scan, custom patterns,
CSV report, duplicate detection by file hash, and safe renaming to avoid overwrites.

Usage examples:
    python organize_photos.py --src ~/Downloads --dst ~/Organized --dry-run
    python organize_photos.py --src ./inbox --dst ./Photos --move --recursive
    python organize_photos.py --src ./inbox --dst ./Photos --copy --report report.csv
    python organize_photos.py --src ./inbox --dst ./Photos --pattern "{Y}/{m}/{Y}-{m}-{d}_{name}{ext}"

Author: Eng.Sameh Awni Salem
License: MIT
"""

import argparse
import csv
import hashlib
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

from PIL import Image
from PIL.ExifTags import TAGS

# Optional HEIC support if pillow-heif is installed
try:
    from pillow_heif import register_heif_opener  # type: ignore
    register_heif_opener()
    HEIF_ENABLED = True
except Exception:  # pragma: no cover
    HEIF_ENABLED = False


DEFAULT_EXTS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".gif", ".webp", ".heic", ".heif"}


def iter_files(root: Path, recursive: bool) -> Iterable[Path]:
    if recursive:
        yield from (p for p in root.rglob("*") if p.is_file())
    else:
        yield from (p for p in root.iterdir() if p.is_file())


def get_exif(image_path: Path) -> Optional[Dict[str, str]]:
    try:
        with Image.open(image_path) as im:
            exif_raw = getattr(im, "_getexif", lambda: None)()
            if not exif_raw:
                return None
            exif: Dict[str, str] = {}
            for tag, value in exif_raw.items():
                name = TAGS.get(tag, tag)
                exif[str(name)] = value
            return exif
    except Exception:
        return None


def infer_datetime(p: Path, exif: Optional[Dict[str, str]]) -> datetime:
    # Try EXIF DateTimeOriginal, DateTime, or fallback to file mtime
    dt_candidates = []
    if exif:
        for key in ("DateTimeOriginal", "DateTimeDigitized", "DateTime"):
            if key in exif:
                dt_candidates.append(str(exif[key]))
    for dt_str in dt_candidates:
        for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(dt_str, fmt)
            except Exception:
                continue
    # Fallback: file modified time
    return datetime.fromtimestamp(p.stat().st_mtime)


def build_target_path(dst_root: Path, pattern: str, dt: datetime, src: Path) -> Path:
    # Allowed tokens in pattern: {Y},{m},{d},{H},{M},{S},{name},{ext}
    mapping = {
        "Y": dt.strftime("%Y"),
        "m": dt.strftime("%m"),
        "d": dt.strftime("%d"),
        "H": dt.strftime("%H"),
        "M": dt.strftime("%M"),
        "S": dt.strftime("%S"),
        "name": src.stem,
        "ext": src.suffix.lower(),
    }
    relative = pattern.format(**mapping)
    return dst_root / relative


def sha256sum(p: Path, chunk_size: int = 65536) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def ensure_unique_path(target: Path) -> Path:
    """Avoid overwriting: add -1, -2 ... before extension if exists."""
    if not target.exists():
        return target
    base = target.with_suffix("")
    ext = target.suffix
    i = 1
    while True:
        candidate = base.parent / f"{base.name}-{i}{ext}"
        if not candidate.exists():
            return candidate
        i += 1


def move_or_copy(src: Path, dst: Path, do_move: bool) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if do_move:
        src.replace(dst)
    else:
        # copy2 preserves metadata
        import shutil
        shutil.copy2(src, dst)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Organize photos into Year/Month folders using EXIF or file time."
    )
    ap.add_argument("--src", required=True, type=Path, help="Source folder containing images")
    ap.add_argument("--dst", required=True, type=Path, help="Destination root folder")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--move", action="store_true", help="Move files instead of copying")
    mode.add_argument("--copy", action="store_true", help="Copy files (default)")
    ap.add_argument("--recursive", action="store_true", help="Scan source folder recursively")
    ap.add_argument("--dry-run", action="store_true", help="Show actions without writing")
    ap.add_argument("--report", type=Path, help="Optional CSV report path to save summary")
    ap.add_argument("--exts", type=str, default=",".join(sorted(DEFAULT_EXTS)),
                    help="Comma-separated list of extensions to include (lowercase with dot)")
    ap.add_argument("--pattern", type=str, default="{Y}/{m}/{Y}-{m}-{d}_{name}{ext}",
                    help="Folder/file pattern using tokens {Y},{m},{d},{H},{M},{S},{name},{ext}")
    ap.add_argument("--log-level", type=str, default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    ap.add_argument("--dedupe", action="store_true", help="Skip files that are duplicates by content hash")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(levelname)s: %(message)s"
    )

    if not args.src.exists() or not args.src.is_dir():
        logging.error("Source folder does not exist or is not a directory: %s", args.src)
        return 2
    args.dst.mkdir(parents=True, exist_ok=True)

    allowed_exts = {e.strip().lower() for e in args.exts.split(",") if e.strip()}
    if not allowed_exts:
        allowed_exts = DEFAULT_EXTS

    do_move = args.move and not args.copy  # default is copy
    totals = {
        "scanned": 0,
        "eligible": 0,
        "processed": 0,
        "skipped_dupe": 0,
        "errors": 0
    }

    # For dedupe across run
    seen_hashes: Dict[str, Path] = {}

    # Prepare report if requested
    report_rows = []
    if args.report:
        report_rows.append(["source", "destination", "action", "timestamp", "reason"])

    for p in iter_files(args.src, args.recursive):
        totals["scanned"] += 1
        ext = p.suffix.lower()
        if ext not in allowed_exts:
            continue
        totals["eligible"] += 1

        try:
            exif = get_exif(p)
            dt = infer_datetime(p, exif)
            target = build_target_path(args.dst, args.pattern, dt, p)
            target = ensure_unique_path(target)

            # Dedupe check
            if args.dedupe:
                try:
                    digest = sha256sum(p)
                    if digest in seen_hashes:
                        logging.info("Skipping duplicate by hash: %s (matches %s)", p, seen_hashes[digest])
                        totals["skipped_dupe"] += 1
                        if args.report:
                            report_rows.append([str(p), "", "skip", datetime.utcnow().isoformat(), "duplicate"])
                        continue
                    seen_hashes[digest] = p
                except Exception as e:
                    logging.warning("Hashing failed for %s: %s", p, e)

            action = "MOVE" if do_move else "COPY"
            logging.info("%s -> %s (%s)", p, target, action if not args.dry_run else f"DRY-{action}")
            if not args.dry_run:
                move_or_copy(p, target, do_move)
            totals["processed"] += 1

            if args.report:
                report_rows.append([str(p), str(target), action if not args.dry_run else f"DRY-{action}", dt.isoformat(), ""])

        except Exception as e:  # catch-all to keep the run going
            totals["errors"] += 1
            logging.error("Error processing %s: %s", p, e)
            if args.report:
                report_rows.append([str(p), "", "error", datetime.utcnow().isoformat(), str(e)])

    # Write report if requested
    if args.report:
        try:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            with args.report.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(report_rows)
            logging.info("Report saved to %s", args.report)
        except Exception as e:
            logging.error("Failed to write report: %s", e)

    # Final summary
    logging.info("Summary: %s", totals)
    print("\n=== SUMMARY ===")
    for k, v in totals.items():
        print(f"{k}: {v}")
    if HEIF_ENABLED:
        print("HEIC/HEIF support: ENABLED")
    else:
        print("HEIC/HEIF support: disabled (install pillow-heif)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
