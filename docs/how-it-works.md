# How it works

A row describes one asset and one expected event source. An asset can appear in several rows when it produces different types of security events. The analyzer uses the supplied reference time or the current UTC time and converts offset timestamps to UTC for comparison.

## Status precedence

1. A source explicitly marked absent or disabled is **Missing**.
2. An enabled source with an event older than its configured threshold is **Stale**.
3. An enabled, verified source with an event at or within the threshold is **Healthy**.
4. The remaining sources are **Unverified** because their evidence is incomplete or insufficient. An event after the reference time is also Unverified unless the source is explicitly absent or disabled.

For a source with a 24-hour threshold, a latest event exactly 24 hours old is still fresh. Consider expected event volume and collection cadence when setting a threshold. A rarely used administrative account may generate few events even when its event pipeline works.

## Reading the report

The analyzer counts every assessed row once. The overall healthy coverage percentage uses all assessed rows as its denominator, including missing and unverified sources. A domain's healthy coverage uses only rows belonging to that domain. Totals therefore depend on the inventory's scope.

Criticality represents the operational importance of an asset or source. Status represents the kind of telemetry issue. Findings are ordered from critical to low criticality. Within each level, Missing comes first, followed by Stale, Unverified, and Healthy. Use the order to decide where to investigate, then confirm the cause in the source settings and collector before making changes.

Learning mode explains the security implications of findings in plain language. For example, a missing firewall feed can make it harder to reconstruct a connection path, and missing identity events can make it harder to determine which account initiated a session.
