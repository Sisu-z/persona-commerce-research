#!/usr/bin/env python3
"""Offline structure, reference, and public-boundary checks; not market verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


EXPECTED_CASE_IDS = {f"B{i:02d}" for i in range(1, 21)}
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
TOKEN_KEY = r"(?:(?:access|refresh|id|auth|login|session|csrf)[_-]?token|xsec[_-]?token|token)"
PUBLIC_PATTERNS = (
    ("machine absolute path", re.compile(
        r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/]|\\\\[A-Za-z0-9])"
        r"|(?<![:/A-Za-z0-9])/(?:Users|home|root|mnt|tmp|private/var)/",
        re.IGNORECASE)),
    ("live Stripe session", re.compile(r"cs_(?:live)_[A-Za-z0-9]+")),
    ("login token value", re.compile(
        rf"(?:(?:[?&]|\b){TOKEN_KEY}\s*(?:=|%3[dD])\s*"
        rf"|[\"']{TOKEN_KEY}[\"']\s*:\s*[\"'])"
        r"[A-Za-z0-9_.%~+/-]{8,}", re.IGNORECASE)),
    ("bearer credential", re.compile(r"\bBearer\s+[A-Za-z0-9_.~+/-]{16,}", re.IGNORECASE)),
)


class Check:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.errors: list[str] = []
        self.notes: list[str] = []

    def error(self, location: str, message: str) -> None:
        self.errors.append(f"{location}: {message}")

    def jsonl(self, relative: str) -> list[dict]:
        path = self.root / relative
        if not path.is_file():
            self.error(relative, "required data file is missing")
            return []
        rows = []
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines()
        except (OSError, UnicodeError):
            self.error(relative, "cannot read UTF-8 data")
            return []
        for line_number, line in enumerate(lines, 1):
            location = f"{relative}:{line_number}"
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                self.error(location, f"invalid JSON ({exc.msg})")
                continue
            if not isinstance(row, dict):
                self.error(location, "record must be an object")
                continue
            row["_check_location"] = location
            rows.append(row)
        return rows

    def public_target(self, location: str, target: str) -> Path | None:
        normalized = target.replace("\\", "/")
        if re.match(r"^[A-Za-z]:", normalized) or normalized.startswith("//"):
            self.error(location, "document must use a repository-relative path")
            return None
        result = (self.root / normalized).resolve()
        try:
            relative = result.relative_to(self.root)
        except ValueError:
            self.error(location, "local link escapes the repository")
            return None
        if any(part in {"private", ".git"} for part in relative.parts):
            self.error(location, "public link points into excluded storage")
            return None
        return result

    def references(self, value, location: str, evidence_ids: set[str]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "evidence_ids":
                    if not isinstance(child, list) or any(not isinstance(i, str) for i in child):
                        self.error(location, "evidence_ids must be a list of strings")
                    elif any(i not in evidence_ids for i in child):
                        self.error(location, "evidence_ids contains an unknown ID")
                else:
                    self.references(child, location, evidence_ids)
        elif isinstance(value, list):
            for child in value:
                self.references(child, location, evidence_ids)

    def evidence(self, rows: list[dict]) -> dict[str, dict]:
        result = {}
        for row in rows:
            location = row["_check_location"]
            record_id = row.get("id")
            if not isinstance(record_id, str) or not record_id:
                self.error(location, "evidence ID must be a nonempty string")
                continue
            if record_id in result:
                self.error(location, "duplicate evidence ID")
            result[record_id] = row
            digest = row.get("sha256")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                self.error(location, "sha256 must contain exactly 64 hex characters")
            if "bytes" in row and (type(row["bytes"]) is not int or row["bytes"] < 0):
                self.error(location, "bytes must be a nonnegative integer")
        if not rows:
            self.error("data/evidence.jsonl", "evidence index is empty")
        return result

    def cases(self, rows: list[dict], evidence_ids: set[str]) -> None:
        found_ids = []
        documents = set()
        unknown_prices = 0
        for row in rows:
            location = row["_check_location"]
            record_id = row.get("id")
            found_ids.append(record_id)
            if not isinstance(record_id, str) or record_id not in EXPECTED_CASE_IDS:
                self.error(location, "case ID must be in B01 through B20")
            if row.get("path_level") not in ("P1", "P2", "P3"):
                self.error(location, "path_level must be P1, P2, or P3")
            if row.get("transaction_level") not in ("T0", "T1"):
                self.error(location, "transaction_level must be T0 or T1 for this run")
            for field in ("paid_or_delivered_by_researcher", "premium_causality_verified"):
                if row.get(field) is not False:
                    self.error(location, f"{field} must be the JSON boolean false")
            document = row.get("document")
            if not isinstance(document, str) or not document.strip():
                self.error(location, "document must be a nonempty relative Markdown path")
            else:
                path = self.public_target(location, document)
                if path is not None:
                    if path.suffix.lower() != ".md" or not path.is_file():
                        self.error(location, "case Markdown document is missing or invalid")
                    if path in documents:
                        self.error(location, "each case must link to its own document")
                    documents.add(path)
            sources = row.get("sources")
            if not isinstance(sources, list) or not sources:
                self.error(location, "sources must be a nonempty list")
            else:
                for source in sources:
                    url = source.get("url") if isinstance(source, dict) else None
                    if not isinstance(url, str):
                        self.error(location, "each source must contain an HTTPS URL")
                        continue
                    try:
                        parsed = urlsplit(url)
                        valid = parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password
                    except ValueError:
                        valid = False
                    if not valid:
                        self.error(location, "source must use HTTPS with a host and no credentials")
            prices = row.get("prices")
            if not isinstance(prices, list):
                self.error(location, "prices must be a list (empty is allowed when unknown)")
            else:
                for index, price in enumerate(prices, 1):
                    price_location = f"{location} price[{index}]"
                    if not isinstance(price, dict):
                        self.error(price_location, "price must be an object")
                        continue
                    if "amount" not in price:
                        self.error(price_location, "amount field is required")
                    amount = price.get("amount")
                    currency_field = "currency" if "currency" in price else "currency_display"
                    if currency_field not in price:
                        self.error(price_location, "currency or currency_display field is required")
                    currency = price.get(currency_field)
                    if not isinstance(price.get("unit"), str) or not price["unit"].strip():
                        self.error(price_location, "unit must be nonempty")
                    if amount is None:
                        conditions = price.get("conditions", price.get("condition", ""))
                        if not isinstance(conditions, str) or not re.search(r"未|待|未知|不明|unknown|unverified|not verified", conditions, re.IGNORECASE):
                            self.error(price_location, "unknown amount must have explicit unverified/unknown conditions")
                        if currency is not None and (not isinstance(currency, str) or not currency.strip()):
                            self.error(price_location, "unknown price currency must be null or nonempty text")
                        unknown_prices += 1
                    else:
                        if type(amount) not in (int, float) or not math.isfinite(amount) or amount < 0:
                            self.error(price_location, "amount must be a finite nonnegative number or an explicit unknown")
                        if not isinstance(currency, str) or not currency.strip():
                            self.error(price_location, "known amount requires nonempty currency")
            self.references(row, location, evidence_ids)
        if len(rows) != 20 or set(i for i in found_ids if isinstance(i, str)) != EXPECTED_CASE_IDS or len(set(i for i in found_ids if isinstance(i, str))) != len(found_ids):
            self.error("data/cases.jsonl", "must contain exactly 20 unique cases B01 through B20")
        if unknown_prices:
            self.notes.append(f"{unknown_prices} explicitly unknown price records retained; not interpreted as zero")

    def markdown_links(self, relative: str, text: str) -> None:
        # Examples inside code are not rendered Markdown links.
        visible = []
        fence = None
        for line in text.splitlines():
            match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
            if match:
                marker = match.group(1)[0]
                if fence is None:
                    fence = marker
                elif fence == marker:
                    fence = None
                continue
            if fence is None:
                visible.append(re.sub(r"`+[^`]*`+", "", line))
        text = "\n".join(visible)
        targets = re.findall(r"!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^)\n]+)\)", text)
        targets += re.findall(r"(?m)^\s{0,3}\[[^\]\n]+\]:\s*(<[^>\n]+>|\S+)", text)
        for raw in targets:
            if not raw.strip():
                continue
            target = raw[1:-1] if raw.startswith("<") and raw.endswith(">") else raw.split()[0]
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            clean = unquote(target.split("#", 1)[0].split("?", 1)[0]).replace("\\", "/")
            if not clean:
                continue
            if clean.startswith("/"):
                candidate = clean.lstrip("/")
            else:
                candidate = (Path(relative).parent / clean).as_posix()
            path = self.public_target(relative, candidate)
            if path is not None and not path.exists():
                self.error(relative, f"missing local Markdown link: {target}")

    def public_files(self) -> int:
        count = 0
        for directory, dirs, files in os.walk(self.root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in {"private", ".git", "__pycache__"}]
            for filename in files:
                path = Path(directory) / filename
                relative = path.relative_to(self.root).as_posix()
                if path.is_symlink():
                    self.error(relative, "public symlinks are not supported by this validator")
                    continue
                try:
                    raw = path.read_bytes()
                    if b"\x00" in raw:
                        continue
                    text = raw.decode("utf-8-sig")
                except UnicodeError:
                    continue  # Binary assets have no text links or token values to scan.
                except OSError:
                    self.error(relative, "cannot read public file")
                    continue
                count += 1
                # Decode URL escapes too, so encoding does not conceal sensitive paths/values.
                for variant in {text, unquote(text)}:
                    for name, pattern in PUBLIC_PATTERNS:
                        match = pattern.search(variant)
                        if match:
                            line_number = variant[:match.start()].count("\n") + 1
                            self.error(f"{relative}:{line_number}", f"prohibited {name} (value not printed)")
                if path.suffix.lower() == ".md":
                    self.markdown_links(relative, text)
        return count

    def private_hashes(self, evidence: dict[str, dict]) -> int:
        private = self.root / "private"
        mapping = private / "evidence-map.json"
        if not private.is_dir() or not mapping.is_file():
            self.notes.append("private evidence/map absent; optional hash audit skipped, public checks remain usable")
            return 0
        try:
            rows = json.loads(mapping.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            self.error("private/evidence-map.json", "cannot read mapping JSON")
            return 0
        if not isinstance(rows, list):
            self.error("private/evidence-map.json", "map must be a list")
            return 0
        found = set()
        verified = 0
        for index, row in enumerate(rows, 1):
            location = f"private/evidence-map.json row[{index}]"
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                self.error(location, "mapping entry requires an ID")
                continue
            record_id = row["id"]
            if record_id in found:
                self.error(location, "duplicate mapped ID")
            found.add(record_id)
            if record_id not in evidence:
                self.error(location, "mapped ID is absent from public evidence")
                continue
            relative = row.get("private_relative_path")
            if not isinstance(relative, str) or re.match(r"^[A-Za-z]:", relative) or Path(relative).is_absolute():
                self.error(location, "private_relative_path must be repository-relative")
                continue
            path = (self.root / relative.replace("\\", "/")).resolve()
            try:
                path.relative_to(private.resolve())
            except ValueError:
                self.error(location, "mapped path escapes private storage")
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                self.error(location, "mapped evidence file is missing/unreadable")
                continue
            public = evidence[record_id]
            if hashlib.sha256(raw).hexdigest() != str(public.get("sha256", "")).lower():
                self.error(location, "saved capture SHA256 differs from public index")
                continue
            if "bytes" in public and len(raw) != public["bytes"]:
                self.error(location, "saved capture byte count differs from public index")
                continue
            verified += 1
        if found != set(evidence):
            self.error("private/evidence-map.json", "mapping IDs must match the public evidence index")
        return verified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-private", action="store_true", help="also verify local evidence map and saved hashes when present")
    args = parser.parse_args()
    check = Check(Path(__file__).resolve().parents[1])
    evidence_rows = check.jsonl("data/evidence.jsonl")
    evidence = check.evidence(evidence_rows)
    for row in evidence_rows:
        check.references(row, row["_check_location"], set(evidence))
    cases = check.jsonl("data/cases.jsonl")
    check.cases(cases, set(evidence))
    public_count = check.public_files()
    private_count = check.private_hashes(evidence) if args.with_private else None
    for note in check.notes:
        print(f"NOTE: {note}")
    for error in dict.fromkeys(check.errors):
        print(f"ERROR: {error}", file=sys.stderr)
    summary = f"{len(cases)} cases, {len(evidence)} evidence entries, {public_count} public text files"
    if private_count is not None:
        summary += f", {private_count} private hashes verified"
    if check.errors:
        print(f"FAIL: {summary}; {len(set(check.errors))} issue(s)", file=sys.stderr)
        return 1
    print(f"PASS: {summary}. Structure/integrity only; market claims are not authenticated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
