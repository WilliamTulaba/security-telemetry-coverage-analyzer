# Student exercises

Use Python 3.11 or newer. Run commands from the project directory. Use `--reference-time 2026-11-20T16:00:00Z` for each exercise unless directed otherwise. Edit copies of the fictional inventories.

## 1. Read a coverage report

**Objective.** Interpret the four statuses and calculate healthy coverage.

**Instructions.** Run the analyzer on `sample_data/small_business.csv` in learning mode. Find one example of each status. Divide the healthy count by the assessed count and convert it to a percentage.

**Expected outcome.** You find 8 healthy, 1 stale, 2 missing, and 1 unverified source. Healthy coverage rounds to 66.7%.

**Extension.** Pick the first listed gap and explain what evidence would confirm its cause.

## 2. Add a fictional asset

**Objective.** Record an expected security source and distinguish enabled logging from verified receipt.

**Instructions.** Copy the small-business inventory and add a fictional workstation with logging enabled and a recent timestamp. Leave verification blank, run the analyzer, then change verification to true and rerun it.

**Expected outcome.** The total rises to 13. The new row moves from Unverified to Healthy after you add verification.

**Extension.** Add a second source on the same workstation with an expected but absent event feed.

## 3. Change a freshness threshold

**Objective.** Predict how a threshold changes the status of a source.

**Instructions.** In a copy of the small-business inventory, change the Office Wi-Fi reporting interval from 24 to 50 hours. Run the analyzer. Change it to 49 hours and rerun.

**Expected outcome.** The event is 50 hours old at the reference time. The Wi-Fi source is Healthy at 50 hours and Stale at 49 hours.

**Extension.** Clear the row's interval and repeat using the `--default-interval-hours` option.

## 4. Introduce a security domain

**Objective.** Interpret domain percentages and explain their denominators.

**Instructions.** In a copy of the college inventory, relabel the Library Wi-Fi domain as `Facilities`. Run the analyzer with `--format markdown`. Compare the domain table and the overall totals with the original report.

**Expected outcome.** Facilities appears as a domain with one assessed source and 0% healthy coverage. The overall counts stay the same.

**Extension.** Add a healthy source in Facilities and calculate its new domain coverage before running the analyzer.

## 5. Extend a report

**Objective.** Modify a report and verify the change with a test.

**Instructions.** Add a count of critical gaps to the Markdown reporter. Use the existing assessment results and count only critical rows with Stale, Missing, or Unverified status. Add a deterministic test with a mix of healthy and gap rows, then run `python -m unittest discover -s tests -v`.

**Expected outcome.** The college sample reports one critical gap at the reference time. The healthy critical identity source is excluded and the stale campus firewall is counted.

**Extension.** Add the same count to the HTML report and test parity between formats.
