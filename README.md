# Security Telemetry Coverage Analyzer

Assess whether expected security log sources are enabled, verified, and reporting recently. The analyzer reads a local CSV inventory and helps students, small businesses, nonprofits, and entry-level analysts identify which logging gaps to investigate first.

It runs on Python 3.11 or newer using the standard library. The tool produces a terminal summary and can export Markdown or standalone HTML reports. Learning mode connects individual findings to incident investigation and security operations.

## Quick start

Clone the repository, then run the script using Python 3.11 or newer. No package installation, account, or API key is required.

```sh
git clone https://github.com/WilliamTulaba/security-telemetry-coverage-analyzer.git
cd security-telemetry-coverage-analyzer
python telemetry_analyzer.py --help
python telemetry_analyzer.py --input sample_data/small_business.csv --output report.html
python telemetry_analyzer.py --input sample_data/college_lab.csv --format markdown --learning-mode
```

The fictional samples use fixed timestamps. Add `--reference-time 2026-11-20T16:00:00Z` to reproduce the sample results. Without it, the analyzer uses the current time and old fictional events can become stale.

## CSV reference

Use one row per expected asset and telemetry source. Include absent sources as rows so the analyzer can count them. Save the file as UTF-8 with the headers below. The first nine headers are required. Add either or both optional headers for stronger evidence.

| Column | Accepted values |
| --- | --- |
| `asset_name` | Asset identifier |
| `asset_type` | Asset category, such as Firewall or Workstation |
| `telemetry_source` | Expected event source, such as Connection events |
| `security_domain` | Grouping label, such as Network, Endpoint, Identity, or Cloud |
| `logging_enabled` | Boolean or blank if unknown |
| `last_event_received` | ISO 8601 timestamp with a time and explicit time zone, such as `2026-11-20T14:00:00Z` or `2026-11-20T09:00:00-05:00`. Leave blank when unknown. |
| `expected_reporting_interval_hours` | Positive hours. A blank uses the default of 24 hours, which can be changed with `--default-interval-hours`. |
| `criticality` | `critical`, `high`, `medium`, or `low`. A blank uses `medium`. |
| `notes` | Optional context for investigation |
| `source_verified` | Optional boolean. Enter true after confirming that the expected events actually reach the intended collector. |
| `source_present` | Optional boolean. Enter false when an expected source is absent. |

Boolean values accept `true`/`false`, `yes`/`no`, or `1`/`0`, ignoring case. A blank means unknown.

## Results

| Status | Meaning |
| --- | --- |
| Healthy | Logging is enabled, the source is verified, and the latest event is at or within the freshness threshold. |
| Stale | Logging is enabled and the latest event exceeds the freshness threshold. |
| Missing | Logging is disabled or the inventory explicitly marks the source absent. |
| Unverified | The inventory lacks enough evidence to establish current coverage. Enabled logging alone is insufficient. |

The healthy coverage rate divides healthy sources by all assessed rows. Domain coverage uses the number of rows in that domain. The small-business sample at the fixed reference time assesses 12 sources, of which 8 are healthy, 1 is stale, 2 are missing, and 1 is unverified. Healthy coverage is 66.7%. See the [example report](examples/small-business-report.md).

## Learn and contribute

- [Getting started](docs/getting-started.md) covers the command line and inventory workflow.
- [How it works](docs/how-it-works.md) explains status precedence, freshness, and denominators.
- [Student exercises](docs/student-exercises.md) cover interpreting findings, recording evidence, adjusting thresholds, grouping by domain, and extending reports.
- [Limitations](docs/limitations.md) covers how to interpret and handle reports.

The analyzer assesses declared telemetry availability and freshness. Establishing detection effectiveness, compliance, and comprehensive security coverage requires separate evidence. The tool reads local files and makes no network connections. Reports can disclose the contents of your inventory, so review what you share.

To contribute, fork the repository, make a focused change, and run `python -m unittest discover -s tests -v`. Open a pull request describing the change and how you verified it. Use fictional data in issues, pull requests, and test fixtures.

## Roadmap

Potential version 1.1 work includes import support for CSV exports from common security tools, historical coverage comparisons, and more advanced student exercises. Other future work includes optional SIEM integrations, visual dashboards, and customizable security-domain guidance.

## Author

**William Tulaba, CISSP**

Cybersecurity leader with more than 20 years of experience across enterprise technology, security engineering, and security operations.

[Official website](https://williamtulaba.com/) · [GitHub](https://github.com/WilliamTulaba)

## License

[MIT](LICENSE)
