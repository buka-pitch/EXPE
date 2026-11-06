# EXPE — build tasks

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked

## M0 — Workspace & foundations
- [x] Create Cargo workspace (`expe-core`, `expe-engine`, `expe-tui`, `expe-cli`, `expe-testkit`)
- [x] Shared lint policy (`unsafe_code` forbidden in libraries, clippy pedantic)
- [x] Domain error taxonomy + result alias
- [x] Core artifact / structure / IOC / finding / report models
- [x] Ports (reader, parser, reporter) and limits
- [x] Risk scoring engine (explainable, category capped)
- [x] CLI skeleton with clap (`analyze`, `info`, `strings`, `iocs`, `batch`, `tui`, `rules`, `schema`)
- [x] TUI skeleton (ratatui 0.30 + crossterm) with panic-safe terminal restore
- [x] rustfmt config + clippy lint policy (`unsafe_code` forbidden, pedantic)
- [x] README with install, CLI/TUI reference, safety model, and development workflow
- [x] CI workflow: rustfmt, clippy, test matrix, MSRV, release artifact
- [ ] `deny.toml` dependency/license checks
- [ ] SECURITY, docs/architecture, docs/threat-model

## M1 — Safe ingestion
- [x] Read-only, regular-files-only reader with size cap
- [x] Streaming md5/sha1/sha256 while reading
- [x] Magic-based format detection (PE / ELF / Mach-O / archive / unknown)
- [x] Panic isolation around third-party parsers
- [x] Tests: empty, truncated, oversized, random bytes

## M2 — Structure extraction
- [x] PE: headers, sections, imports, exports, overlay, debug/PDB, TLS, .NET, signature, rich header, version info
- [x] ELF: header, segments, sections, interpreter, libraries, rpath/runpath, build-id, symbols
- [x] Mach-O: header, segments, dylibs, entry (basic)
- [x] PE imphash (pefile-compatible normalization)
- [x] Synthetic PE test fixture builder + parser tests
- [x] `info` command with human output

## M3 — Strings & entropy
- [x] Shannon entropy (whole file + per section)
- [x] ASCII + UTF-16LE string scanner with offsets, dedupe, caps
- [x] `strings` command with regex filter, encoding selector, limit
- [x] Tests: offsets, UTF-16, dedupe, limits, entropy edge cases

## M4 — IOC engine
- [x] Embedded TOML rule pack + user rule loading/overrides
- [x] RegexSet single-pass candidate detection over strings
- [x] Typed validators (IP scope, domain, URL, email, paths, wallets, onion)
- [x] Structural IOC sources (imports, section names, exports, PDB)
- [x] Offset tracing, dedupe, occurrence counts, confidence
- [x] Defanging formatter
- [x] `iocs` command + `rules list/check`
- [x] Tests: validators, false-positive corpus, rule loading errors

## M5 — Heuristics & scoring
- [x] Generic entropy findings
- [x] PE packer signatures, RWX sections, EP anomalies, low imports, overlay, unsigned, timestamp, TLS, PDB leak
- [x] Suspicious import matrix mapped to MITRE ATT&CK
- [x] ELF W+X, static, stripped, RPATH, packer, suspicious symbols
- [x] Risk scoring + verdict + breakdown
- [x] `analyze` end-to-end + golden JSON assertions
- [x] Tests: each heuristic + score saturation/category caps

## M6 — Reporting & batch
- [x] Stable JSON report (`schema_version`, deterministic ordering)
- [x] Text and Markdown reporters with terminal-escape sanitization
- [x] Defang option
- [x] Batch scanning with recursive discovery, `--jobs`, JSONL streaming
- [x] Exit codes + `--fail-on`
- [x] JSON Schema command (schemars)
- [x] Integration tests (assert_cmd) for exit codes and JSON validity

## M7 — TUI foundation (smart, modern UX)
- [x] Alternate-screen lifecycle, panic hook + restore guard, size/tty guards
- [x] MVU state: `Msg` / `update` / effects; background analysis worker with progress + cancel
- [x] Design system: palette, severity colors, rounded cards, spacing, responsive layout
- [x] Header with file identity + risk badge + live stage progress
- [x] Sidebar navigation with icons/keys and active indicator
- [x] Overview screen (risk gauge, KPI cards, top findings, section entropy bars)
- [x] Structure screen (sections table, import tree, metadata)
- [x] Strings screen (virtualized list, live regex filter, offset/encoding columns)
- [x] IOCs screen (kind grouping, scope/confidence badges, detail pane)
- [x] Findings screen (severity sorting, evidence + ATT&CK)
- [x] Help overlay (opaque card), toast notifications, footer context keys, empty/error states
- [x] Open-file screen when no path is supplied
- [x] Unit tests for update/filter/sanitize + TestBackend render smoke test

## M8 — TUI advanced
- [x] Export JSON from TUI (`e`) — non-clobbering paths + success/error toast
- [x] Copy IOC/finding to clipboard (`c`, OSC52) with success/error toast
- [x] Hex view with offset jump (from retained bytes)
- [ ] Batch queue screen
- [ ] In-app file picker (directory browsing)
- [ ] Command palette

## M9 — Hardening
- [x] Terminal-injection sanitizer tests (ESC, bidi, NUL)
- [ ] Fuzz targets (`parse`, `strings`, `analyze`)
- [ ] Property tests (never panic on arbitrary bytes, deterministic output)
- [ ] Criterion benchmarks
- [ ] CI matrix, coverage, cargo-deny, release binaries
- [ ] Documentation polish
