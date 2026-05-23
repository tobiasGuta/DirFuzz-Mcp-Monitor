# Update Log

This file tracks user-facing fixes and noteworthy updates. Keep future bugfix notes here instead of scattering them across other Markdown docs. Add new entries with the date they were made.

## 2026-05-23
- Fixed raw request/response capture for hidden-parameter fuzzing when `--save-raw` is enabled.
- Prevented canceled requests from being counted as network failures or retry noise.
- Removed the default 60-second scan cap so normal scans run until completion unless `--max-duration` is set.
- Made the TUI exit cleanly when the engine result stream closes instead of freezing on partial progress.
- Stopped auto param-fuzz from triggering on redirect-only responses.
