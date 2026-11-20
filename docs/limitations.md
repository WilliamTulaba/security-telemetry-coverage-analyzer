# Limitations

This tool assesses the telemetry declared in a CSV. It does not query assets, validate collector evidence, inspect raw logs, or discover sources omitted from the inventory. Record each expected source and verify collector receipt separately. An inventory can overstate coverage when important expected sources are omitted.

A recent event is evidence of freshness for the recorded source. It does not measure event completeness, parsing quality, alerting, retention, or detection effectiveness. A stale result can follow an interrupted pipeline or simply a quiet source. Review expected activity and collector health before acting. The analyzer provides no compliance determination.

Reports can contain asset labels and notes copied from the inventory. Keep sensitive reports in an appropriate location and use the fictional examples when sharing demonstrations. The analyzer reads and writes local files. It does not transmit data or need elevated privileges.
