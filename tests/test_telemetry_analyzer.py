"""Deterministic analysis, CSV, report, and command-line checks."""

from contextlib import redirect_stderr, redirect_stdout
import csv
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import tempfile
import unittest

from telemetry_analyzer import (
    InventoryError,
    REQUIRED_COLUMNS,
    Source,
    Status,
    analyze,
    classify,
    load_inventory,
    main,
    parse_timestamp,
    render_report,
)

REFERENCE = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)
SOURCE = Source(
    "fictional-device", "Workstation", "Process events", "Endpoint",
    True, REFERENCE - timedelta(hours=2), 24.0, "high", "", True, True,
)
COLUMNS = (*REQUIRED_COLUMNS, "source_verified", "source_present")
ROW = ("invented-device", "Firewall", "Connection events", "Network", "yes",
       "2026-01-15T10:00:00Z", "24", "high", "Fictional", "yes", "yes")


class AnalysisTests(unittest.TestCase):
    def test_healthy_telemetry(self):
        self.assertEqual(classify(SOURCE, REFERENCE).status, Status.HEALTHY)

    def test_stale_telemetry_even_without_verification_flag(self):
        source = replace(SOURCE, last_event_received=REFERENCE - timedelta(hours=25), source_verified=None)
        self.assertEqual(classify(source, REFERENCE).status, Status.STALE)

    def test_missing_telemetry(self):
        for fields in ({"logging_enabled": False}, {"source_present": False}):
            with self.subTest(fields=fields):
                self.assertEqual(classify(replace(SOURCE, **fields), REFERENCE).status, Status.MISSING)

    def test_unverified_telemetry(self):
        for fields in (
            {"source_verified": None}, {"source_verified": False}, {"last_event_received": None},
            {"logging_enabled": None},
        ):
            with self.subTest(fields=fields):
                self.assertEqual(classify(replace(SOURCE, **fields), REFERENCE).status, Status.UNVERIFIED)

    def test_future_event_is_unverified(self):
        finding = classify(replace(SOURCE, last_event_received=REFERENCE + timedelta(seconds=1)), REFERENCE)
        self.assertEqual(finding.status, Status.UNVERIFIED)
        self.assertIn("after the reference time", finding.explanation)

    def test_future_event_explained_when_logging_state_is_unknown(self):
        source = replace(SOURCE, logging_enabled=None, last_event_received=REFERENCE + timedelta(seconds=1))
        finding = classify(source, REFERENCE)
        self.assertEqual(finding.status, Status.UNVERIFIED)
        self.assertIn("after the reference time", finding.explanation)

    def test_freshness_threshold_boundaries(self):
        bounds = (
            (timedelta(hours=24) - timedelta(microseconds=1), Status.HEALTHY),
            (timedelta(hours=24), Status.HEALTHY),
            (timedelta(hours=24) + timedelta(microseconds=1), Status.STALE),
        )
        for age, expected in bounds:
            with self.subTest(age=age):
                self.assertEqual(classify(replace(SOURCE, last_event_received=REFERENCE - age), REFERENCE).status, expected)

    def test_timezone_handling(self):
        self.assertEqual(parse_timestamp("2026-01-15T07:00:00-05:00"), REFERENCE)
        self.assertEqual(parse_timestamp("2026-01-15T17:30+05:30"), REFERENCE)
        self.assertIs(parse_timestamp("2026-01-15T12:00:00Z").tzinfo, timezone.utc)

    def test_invalid_timestamps(self):
        for text in (
            "2026-01-15T12:00:00", "2026-01-15", "2026-02-31T12:00:00Z",
            "2026-01-15T12:00:00+00:99",
        ):
            with self.subTest(text=text):
                with self.assertRaises(InventoryError):
                    parse_timestamp(text)

    def test_findings_sort_by_criticality_then_severity(self):
        findings = analyze(
            [replace(SOURCE, criticality="low", logging_enabled=False),
             replace(SOURCE, logging_enabled=False), SOURCE, replace(SOURCE, criticality="critical")],
            REFERENCE,
        )
        self.assertEqual(
            [(item.source.criticality, item.status) for item in findings],
            [("critical", Status.HEALTHY), ("high", Status.MISSING),
             ("high", Status.HEALTHY), ("low", Status.MISSING)],
        )


class InventoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "inventory.csv"

    def write_inventory(self, columns=COLUMNS, rows=(ROW,)):
        with self.path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(columns)
            writer.writerows(rows)

    def test_missing_csv_columns(self):
        self.write_inventory(("asset_name",), ())
        with self.assertRaisesRegex(InventoryError, "Missing CSV columns: asset_type"):
            load_inventory(self.path)

    def test_empty_inventory(self):
        self.write_inventory(rows=())
        with self.assertRaisesRegex(InventoryError, "no data rows"):
            load_inventory(self.path)

    def test_invalid_timestamp_reports_field_and_line(self):
        self.write_inventory(rows=((*ROW[:5], "yesterday", *ROW[6:]),))
        with self.assertRaisesRegex(InventoryError, "CSV line 2: last_event_received"):
            load_inventory(self.path)

    def test_validates_record_width(self):
        self.write_inventory(rows=(ROW[:-1],))
        with self.assertRaisesRegex(InventoryError, "Expected 11 fields, found 10"):
            load_inventory(self.path)

    def test_blank_interval_uses_configured_default(self):
        self.write_inventory(rows=((*ROW[:6], "", *ROW[7:]),))
        self.assertEqual(load_inventory(self.path, default_interval=3)[0].interval_hours, 3)

    def test_original_columns_work_without_verification(self):
        self.write_inventory(REQUIRED_COLUMNS, (ROW[:9],))
        self.assertIsNone(load_inventory(self.path)[0].source_verified)

    def test_nonfinite_and_nonpositive_thresholds_fail(self):
        for value in ("0", "-2", "NaN", "inf"):
            with self.subTest(value=value):
                self.write_inventory(rows=((*ROW[:6], value, *ROW[7:]),))
                with self.assertRaisesRegex(InventoryError, "expected_reporting_interval_hours"):
                    load_inventory(self.path)

    def test_cli_infers_html_and_prints_summary(self):
        self.write_inventory()
        output = self.path.with_suffix(".html")
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["--input", str(self.path), "--output", str(output),
                              "--reference-time", "2026-01-15T12:00:00Z"])
        self.assertEqual(exit_code, 0)
        self.assertIn("Healthy: 1 (100.0%)", stdout.getvalue())
        self.assertIn("<caption>Findings</caption>", output.read_text(encoding="utf-8"))

    def test_cli_refuses_to_overwrite_input(self):
        self.write_inventory()
        before = self.path.read_bytes()
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["--input", str(self.path), "--output", str(self.path)])
        self.assertEqual(result, 2)
        self.assertIn("must differ", stderr.getvalue())
        self.assertEqual(self.path.read_bytes(), before)

    def test_cli_rejects_output_aliases_of_input(self):
        self.write_inventory()
        before = self.path.read_bytes()
        symlink = self.path.with_suffix(".html")
        hardlink = self.path.with_suffix(".md")
        symlink.symlink_to(self.path)
        hardlink.hardlink_to(self.path)
        for output in (symlink, hardlink):
            with self.subTest(output=output), redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(main(["--input", str(self.path), "--output", str(output)]), 2)
                self.assertIn("must differ", stderr.getvalue())
                self.assertTrue(output.samefile(self.path))
        self.assertEqual(self.path.read_bytes(), before)

    def test_cli_handles_output_symlink_loop(self):
        self.write_inventory()
        output = self.path.with_suffix(".html")
        output.symlink_to(output.name)
        with redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(main(["--input", str(self.path), "--output", str(output)]), 1)
        self.assertIn("Error:", stderr.getvalue())
        self.assertTrue(output.is_symlink())

    def test_cli_io_error_has_distinct_exit_code(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["--input", str(self.path)])
        self.assertEqual(result, 1)
        self.assertIn("Error:", stderr.getvalue())


class ReportTests(unittest.TestCase):
    def test_percentages_include_unverified_and_use_per_domain_denominators(self):
        findings = analyze(
            [SOURCE, replace(SOURCE, source_verified=None),
             replace(SOURCE, security_domain="Identity", logging_enabled=False),
             replace(SOURCE, security_domain="Cloud", last_event_received=REFERENCE - timedelta(days=2))],
            REFERENCE,
        )
        report = render_report(findings, REFERENCE, "terminal")
        self.assertIn("Assessed: 4 | Healthy: 1 (25.0%) | Stale: 1 (25.0%) | Missing: 1 (25.0%) | Unverified: 1 (25.0%)", report)
        self.assertIn("Domain: Endpoint | Assessed: 2 | Healthy: 1 (50.0%)", report)

    def test_html_report_escapes_inventory_values(self):
        findings = analyze([replace(SOURCE, notes='<script>"example"</script>')], REFERENCE)
        report = render_report(findings, REFERENCE, "html", learning_mode=True)
        self.assertIn("<!doctype html>", report)
        self.assertIn('<th scope="col">Why it matters</th>', report)
        self.assertIn("&lt;script&gt;&quot;example&quot;&lt;/script&gt;", report)
        self.assertNotIn("<script>", report)
        self.assertIn("Endpoint logs help analysts", report)

    def test_markdown_report_escapes_inventory_values(self):
        findings = analyze([replace(SOURCE, notes="A | <b>example</b>")], REFERENCE)
        report = render_report(findings, REFERENCE, "markdown")
        self.assertIn("## Findings", report)
        self.assertIn("&#124; &#60;b&#62;example", report)
        self.assertIn("100.0%", report)
        self.assertNotIn("<b>", report)
        self.assertNotIn("Why it matters", report)


if __name__ == "__main__":
    unittest.main()
