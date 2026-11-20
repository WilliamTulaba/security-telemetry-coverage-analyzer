# Getting started

1. Check that `python --version` reports 3.11 or newer. If your system uses `python3`, use that command throughout.
2. Clone the repository or download the source from GitHub. Open a terminal in the project directory.
3. Run the small-business assessment at the sample reference time.

   ```sh
   python telemetry_analyzer.py --input sample_data/small_business.csv --reference-time 2026-11-20T16:00:00Z
   ```

4. Export the same assessment as HTML, then open the report in your browser.

   ```sh
   python telemetry_analyzer.py --input sample_data/small_business.csv --reference-time 2026-11-20T16:00:00Z --output report.html --learning-mode
   ```

   Use `--format markdown` to emit Markdown to standard output, or pair it with `--output report.md` to save a file. Saving a report also prints a short summary to the terminal. For a plain-text file, use `--output report.txt`. Run `python telemetry_analyzer.py --help` for current options.

5. To assess your own environment, copy a sample CSV and replace its rows with entries for the telemetry you expect to receive. Use the latest collector receipt timestamp and record whether you confirmed receipt. Keep the inventory and reports local if they contain internal information.

The CLI returns 0 after a successful assessment, including when it finds coverage gaps. It returns 2 for invalid arguments or inventory data and 1 when it cannot read or write a file. Read the error and correct the indicated field or path before retrying.
