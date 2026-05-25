# Update Log

This file tracks user-facing fixes and noteworthy updates. Keep future bugfix notes here instead of scattering them across other Markdown docs. Add new entries with the date they were made.

## 2026-05-25
- Fixed recursive scanning noise where child routes such as `api/api`, `api/api/user`, and `api/user/api` could be reported when they returned the same response fingerprint as an already-seen parent or canonical route.
- Added default-on recursive pruning through `--recursive-prune` to report low-value static/resource branches once, then avoid spending recursive depth under paths like `includes/fonts`.
- Made recursive pruning conservative for pentest workflows: static-looking branches are still recursively scanned when their listings expose interesting names such as `config`, `.bak`, `.old`, `.env`, `secret`, `admin`, `api`, or `upload`.

## 2026-05-23
- Removed the built-in hidden-parameter brute-force list and made parameter fuzzing opt-in through `--param-wordlist` / `--param-wordlists`.
- Disabled automatic parameter fuzzing when no parameter wordlist is provided.
- Added smart parameter hint extraction from response text, error messages, HTML forms, and links to augment configured parameter wordlists.
- Deduplicated hidden-parameter probes across repeated URLs that differ only by query values, such as multiple `jobs.php?id=*` findings.
- Fixed redirect-followed parameter fuzzing to probe the final canonical URL instead of the pre-redirect URL, reducing `301` false positives on paths like `/api`.
- Added neutral control probes for hidden-parameter fuzzing to suppress pages that change generically for any query string.
- Added `--harvest-response` for generic response-driven endpoint discovery, including JSON API bodies that list child endpoints.
- Added `--harvest-response-depth` and `--harvest-response-fetch` to tune bounded follow-up crawling for response-driven harvesting.
- Made live scan responses feed response-harvest discoveries back into the active queue, so paths revealed by endpoints like `/api/` are scanned during the same run.
- Fixed harvest progress accounting so harvested jobs count toward total progress instead of pushing scans past 100%.
- Fixed raw request/response capture for hidden-parameter fuzzing when `--save-raw` is enabled.
- Prevented canceled requests from being counted as network failures or retry noise.
- Removed the default 60-second scan cap so normal scans run until completion unless `--max-duration` is set.
- Made the TUI exit cleanly when the engine result stream closes instead of freezing on partial progress.
- Stopped auto param-fuzz from triggering on redirect-only responses.
