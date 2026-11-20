#!/usr/bin/env python3
"""Assess declared security telemetry availability and freshness from CSV."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from html import escape
import math
from pathlib import Path
import re
import sys
import tempfile
from typing import Callable, Sequence, TypeVar

REQUIRED_COLUMNS = (
    "asset_name",
    "asset_type",
    "telemetry_source",
    "security_domain",
    "logging_enabled",
    "last_event_received",
    "expected_reporting_interval_hours",
    "criticality",
    "notes",
)
CRITICALITY = ("critical", "high", "medium", "low")
DEFAULT_INTERVAL = 24.0
FieldValue = TypeVar("FieldValue")
SCOPE = (
    "This report assesses declared telemetry availability and freshness. "
    "It does not measure detection effectiveness or complete security coverage."
)


class InventoryError(ValueError):
    """Identify invalid input or CLI settings."""


class Status(StrEnum):
    """Possible outcomes for an inventory row."""

    HEALTHY = "Healthy"
    STALE = "Stale"
    MISSING = "Missing"
    UNVERIFIED = "Unverified"


SEVERITY = {
    Status.MISSING: 0,
    Status.STALE: 1,
    Status.UNVERIFIED: 2,
    Status.HEALTHY: 3,
}
OUTCOME = {
    Status.HEALTHY: (
        "A verified source has a recent event within the freshness threshold.",
        "Continue checking recent events during routine monitoring reviews.",
    ),
    Status.STALE: (
        "The last reported event is older than the freshness threshold.",
        "Check the event producer, forwarding path, ingestion, and clocks.",
    ),
    Status.MISSING: (
        "Logging is disabled or the expected source is explicitly marked absent.",
        "Enable or restore the source and confirm that a new event arrives.",
    ),
    Status.UNVERIFIED: (
        "The inventory lacks sufficient reliable evidence of current coverage.",
        "Confirm logging and source presence, then record a verified recent event and check clocks.",
    ),
}
DOMAIN_LESSONS = {
    "network": "Firewall and network logs help investigators reconstruct connections and identify blocked traffic.",
    "endpoint": "Endpoint logs help analysts see suspicious process activity and trace what happened on a device.",
    "identity": "Authentication events help analysts spot unusual sign-ins and investigate account misuse.",
    "cloud": "Cloud audit logs show who changed cloud resources, which helps establish an incident timeline.",
}


@dataclass(frozen=True)
class Source:
    """Validated declaration of one expected telemetry source."""

    asset_name: str
    asset_type: str
    telemetry_source: str
    security_domain: str
    logging_enabled: bool | None
    last_event_received: datetime | None
    interval_hours: float
    criticality: str
    notes: str
    source_verified: bool | None
    source_present: bool | None


@dataclass(frozen=True)
class Finding:
    """Analysis result for one source."""

    source: Source
    status: Status
    explanation: str


def parse_timestamp(value: str) -> datetime:
    """Parse an offset-aware ISO 8601 timestamp and normalize it to UTC."""
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}"
        r"(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})",
        value,
    ):
        raise InventoryError(f"{value!r} must be ISO 8601 with a UTC offset or Z")
    if not value.endswith("Z") and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise InventoryError(f"{value!r} has an invalid UTC offset")
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise InventoryError(f"{value!r} is not a valid timestamp") from exc


def parse_flag(value: str) -> bool | None:
    """Parse a tri-state CSV boolean."""
    match value.casefold():
        case "true" | "yes" | "1":
            return True
        case "false" | "no" | "0":
            return False
        case "":
            return None
        case _:
            raise InventoryError(f"{value!r} must be true, false, yes, no, 1, 0, or blank")


def parse_interval(value: str) -> float:
    """Require finite, positive hours."""
    try:
        hours = float(value)
    except ValueError as exc:
        raise InventoryError(f"{value!r} must be a finite number of hours greater than zero") from exc
    if not math.isfinite(hours) or hours <= 0:
        raise InventoryError(f"{value!r} must be a finite number of hours greater than zero")
    return hours


def parse_source(row: dict[str, str], default_interval: float) -> Source:
    """Validate a stripped CSV row and label field-level errors."""
    for field in REQUIRED_COLUMNS[:4]:
        if not row[field]:
            raise InventoryError(f"{field} cannot be blank")

    def parsed(
        field: str, parser: Callable[[str], FieldValue], default: FieldValue | None = None
    ) -> FieldValue | None:
        value = row.get(field, "")
        try:
            return parser(value) if value else default
        except InventoryError as exc:
            raise InventoryError(f"{field}: {exc}") from exc

    criticality = row["criticality"].casefold() or "medium"
    if criticality not in CRITICALITY:
        raise InventoryError("criticality must be critical, high, medium, low, or blank")
    interval = parsed("expected_reporting_interval_hours", parse_interval)
    return Source(
        asset_name=row["asset_name"],
        asset_type=row["asset_type"],
        telemetry_source=row["telemetry_source"],
        security_domain=row["security_domain"],
        logging_enabled=parsed("logging_enabled", parse_flag),
        last_event_received=parsed("last_event_received", parse_timestamp),
        interval_hours=default_interval if interval is None else interval,
        criticality=criticality,
        notes=row["notes"],
        source_verified=parsed("source_verified", parse_flag),
        source_present=parsed("source_present", parse_flag),
    )


def load_inventory(path: Path, default_interval: float = DEFAULT_INTERVAL) -> list[Source]:
    """Load a UTF-8 CSV inventory with field and line-number validation."""
    sources: list[Source] = []
    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file, strict=True)
        try:
            fields = [field.strip() for field in next(reader, [])]
            missing = [name for name in REQUIRED_COLUMNS if name not in fields]
            if missing:
                raise InventoryError(f"Missing CSV columns: {', '.join(missing)}")
            if len(set(fields)) != len(fields):
                raise InventoryError("CSV column names must be unique")
            for values in reader:
                if not values:
                    continue
                try:
                    if len(values) != len(fields):
                        raise InventoryError(f"Expected {len(fields)} fields, found {len(values)}")
                    row = dict(zip(fields, (value.strip() for value in values), strict=True))
                    sources.append(parse_source(row, default_interval))
                except InventoryError as exc:
                    raise InventoryError(f"CSV line {reader.line_num}: {exc}") from exc
        except csv.Error as exc:
            raise InventoryError(f"CSV line {reader.line_num}: {exc}") from exc
    if not sources:
        raise InventoryError("The CSV inventory has no data rows")
    return sources


def classify(source: Source, reference_time: datetime) -> Finding:
    """Apply missing, freshness, and verification rules in priority order."""
    if source.logging_enabled is False or source.source_present is False:
        status = Status.MISSING
    elif source.logging_enabled is not True or source.last_event_received is None:
        status = Status.UNVERIFIED
    elif source.last_event_received > reference_time:
        return Finding(source, Status.UNVERIFIED, "The latest event is after the reference time. Check the event timestamp and clocks.")
    elif (reference_time - source.last_event_received).total_seconds() / 3600 > source.interval_hours:
        status = Status.STALE
    elif source.source_verified is True:
        status = Status.HEALTHY
    else:
        status = Status.UNVERIFIED
    return Finding(source, status, OUTCOME[status][0])


def analyze(sources: Sequence[Source], reference_time: datetime) -> list[Finding]:
    """Classify each row and order findings by criticality and severity."""
    return sorted(
        (classify(source, reference_time) for source in sources),
        key=lambda finding: (
            CRITICALITY.index(finding.source.criticality),
            SEVERITY[finding.status],
            finding.source.asset_name.casefold(),
            finding.source.telemetry_source.casefold(),
        ),
    )


def learning_note(finding: Finding) -> str:
    """Explain the investigation value and freshness implications of a result."""
    domain = finding.source.security_domain.casefold()
    topic = next((key for key in DOMAIN_LESSONS if key in domain), None)
    if topic is None and "firewall" in domain:
        topic = "network"
    lesson = DOMAIN_LESSONS.get(topic, "Security logs help analysts reconstruct activity during an investigation.")
    impact = {
        Status.HEALTHY: "A verified recent event gives analysts some evidence that this source is reporting.",
        Status.STALE: "Stale telemetry can create a blind spot while analysts expect the source to be reporting.",
        Status.MISSING: "Without this telemetry, investigators may need other records to piece together what happened.",
        Status.UNVERIFIED: "Checking actual event delivery helps analysts avoid relying on an assumption.",
    }
    return f"{lesson} {impact[finding.status]}"


def report_tables(
    findings: Sequence[Finding], learning_mode: bool
) -> list[tuple[str, tuple[str, ...], list[tuple[str, ...]]]]:
    """Build the same ordered tables for all three output formats."""
    def counts(group: Sequence[Finding]) -> tuple[str, ...]:
        total = len(group)
        outcomes = [sum(finding.status == status for finding in group) for status in Status]
        return (
            str(total),
            *(f"{count} ({count / total:.1%})" if total else "0 (n/a)" for count in outcomes),
        )

    summary_columns = ("Assessed", *(status.value for status in Status))
    domains: dict[str, list[Finding]] = {}
    rows: list[tuple[str, ...]] = []
    for finding in findings:
        source = finding.source
        domains.setdefault(source.security_domain, []).append(finding)
        row = (
            source.asset_name, source.asset_type, source.telemetry_source, source.security_domain,
            source.criticality.capitalize(), finding.status.value,
            source.last_event_received.isoformat() if source.last_event_received else "",
            f"{source.interval_hours:g}", finding.explanation, OUTCOME[finding.status][1], source.notes,
        )
        rows.append((*row, learning_note(finding)) if learning_mode else row)
    finding_columns = (
        "Asset", "Asset type", "Telemetry source", "Security domain", "Criticality", "Status",
        "Last event (UTC)", "Threshold (hours)", "Explanation", "Recommendation", "Notes",
    )
    if learning_mode:
        finding_columns += ("Why it matters",)
    return [
        ("Summary", summary_columns, [counts(findings)]),
        ("Security domains", ("Domain", *summary_columns), [
            (name, *counts(domains[name])) for name in sorted(domains, key=str.casefold)
        ]),
        ("Findings", finding_columns, rows),
    ]


def plain_cell(value: str) -> str:
    """Remove terminal control characters while keeping report text readable."""
    return "".join(char if char.isprintable() else " " for char in value)


def markdown_cell(value: str) -> str:
    """Render untrusted input as literal text within a Markdown table cell."""
    return re.sub(r"[&<>|\\`*_[\]~!:@]", lambda match: f"&#{ord(match[0])};", plain_cell(value))


def render_report(
    findings: Sequence[Finding], reference_time: datetime, report_format: str,
    learning_mode: bool = False,
) -> str:
    """Render a terminal, Markdown, or self-contained HTML report."""
    title = "Security Telemetry Coverage Report"
    intro = (
        f"Reference time (UTC): {reference_time.isoformat()}",
        SCOPE,
        "Coverage is the Healthy share of assessed rows. Every status percentage uses all assessed rows in its table row as the denominator.",
    )
    tables = report_tables(findings, learning_mode)
    if report_format == "html":
        parts = [
            '<!doctype html>', '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{title}</title>",
            "<style>body{font:1rem/1.5 system-ui,sans-serif;margin:2rem;color:#172033;background:#fff}"
            "table{border-collapse:collapse;width:100%}th,td{border:1px solid #b4bbc6;padding:.5rem;"
            "text-align:left;vertical-align:top;overflow-wrap:anywhere}"
            "th{background:#e8edf6}caption{text-align:left;font-size:1.25rem;font-weight:bold}"
            ".table-wrap{overflow:auto;margin-block:1.5rem}</style></head><body><main>",
            f"<h1>{title}</h1>",
            *(f"<p>{escape(line)}</p>" for line in intro),
        ]
        for name, columns, rows in tables:
            parts.append(f'<div class="table-wrap" tabindex="0" role="region" aria-label="{escape(name)}">')
            parts.append(f"<table><caption>{escape(name)}</caption><thead><tr>")
            parts.extend(f'<th scope="col">{escape(column)}</th>' for column in columns)
            parts.append("</tr></thead><tbody>")
            parts.extend("<tr>" + "".join(f"<td>{escape(cell)}</td>" for cell in row) + "</tr>" for row in rows)
            parts.append("</tbody></table></div>")
        parts.append("</main></body></html>")
        return "\n".join(parts) + "\n"
    if report_format == "markdown":
        parts = [f"# {title}", "", *[line for item in intro for line in (item, "")]]
        for name, columns, rows in tables:
            parts.extend((f"## {name}", "", "| " + " | ".join(columns) + " |"))
            parts.append("| " + " | ".join("---" for _ in columns) + " |")
            parts.extend("| " + " | ".join(map(markdown_cell, row)) + " |" for row in rows)
            parts.append("")
        return "\n".join(parts)
    parts = [title, *intro]
    for name, columns, rows in tables:
        parts.extend(("", name))
        for row in rows:
            if name == "Findings":
                parts.extend(f"  {label}: {plain_cell(value)}" for label, value in zip(columns, row) if value)
                parts.append("")
            else:
                parts.append("  " + " | ".join(f"{label}: {plain_cell(value)}" for label, value in zip(columns, row)))
    return "\n".join(parts).rstrip() + "\n"


def write_report(path: Path, report: str) -> None:
    """Replace the destination only after successfully writing the whole report."""
    file = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=".telemetry-", delete=False
    )
    temporary = Path(file.name)
    try:
        with file:
            file.write(report)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI, returning 0 on success, 1 on I/O errors, or 2 on invalid input."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="UTF-8 CSV inventory")
    parser.add_argument("--output", type=Path, help="Report path. With no path, print to standard output.")
    parser.add_argument("--format", choices=("terminal", "markdown", "html"), help="Report format, inferred from the output suffix when possible")
    parser.add_argument("--learning-mode", action="store_true", help="Explain why each finding matters")
    parser.add_argument("--reference-time", help="ISO 8601 timestamp with an offset or Z. Defaults to current UTC time.")
    parser.add_argument("--default-interval-hours", default=str(DEFAULT_INTERVAL), help="Hours to use when an inventory row has no threshold (default: 24)")
    args = parser.parse_args(argv)
    try:
        reference_time = parse_timestamp(args.reference_time) if args.reference_time is not None else datetime.now(timezone.utc)
        default_interval = parse_interval(args.default_interval_hours)
        if args.output and (
            args.input.resolve() == args.output.resolve()
            or (args.output.exists() and args.input.exists() and args.output.samefile(args.input))
        ):
            raise InventoryError("The report path must differ from the input inventory path")
        report_format = args.format
        if report_format is None:
            if args.output:
                formats = {".html": "html", ".htm": "html", ".md": "markdown", ".markdown": "markdown", ".txt": "terminal"}
                report_format = formats.get(args.output.suffix.casefold())
                if report_format is None:
                    raise InventoryError("Cannot infer the report format from the output suffix. Specify --format.")
            else:
                report_format = "terminal"
        findings = analyze(load_inventory(args.input, default_interval), reference_time)
        report = render_report(findings, reference_time, report_format, args.learning_mode)
        if args.output:
            write_report(args.output, report)
            print(render_report(findings, reference_time, "terminal", args.learning_mode).split("\n\nFindings\n", 1)[0])
            print(f"Report written to {str(args.output)!r}")
        else:
            print(report, end="")
    except (InventoryError, UnicodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
