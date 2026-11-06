# EXPE — AI Agent Skill Reference

**EXPE** (short for **explore PE**) is a safe binary triage tool for PE, ELF, and Mach-O files. It parses structure, extracts strings/IOCs, detects packers and suspicious imports, scores risk, and outputs structured reports — **never executing the sample**.

---

## Quick Start

```bash
# Full analysis (text, JSON, or Markdown)
expe analyze /path/to/sample

# Structure only
expe info /path/to/sample

# Strings with regex filter
expe strings /path/to/sample --regex "http" --encoding both

# IOCs only
expe iocs /path/to/sample --types ipv4,domain,url

# Batch scan directory
expe batch /samples --recursive --format jsonl --jobs 4

# Interactive TUI
expe tui /path/to/sample

# Rule management
expe rules list
expe rules check ./my-rules.toml

# JSON Schema
expe schema
```

---

## Commands Reference

### `analyze` — Full Analysis Report

```bash
expe analyze [OPTIONS] <PATH>
```

| Option | Description | Default |
|--------|-------------|---------|
| `--format <text\|json\|markdown>` | Output format | `text` |
| `-o, --output <FILE>` | Write to file instead of stdout | — |
| `--include-strings` | Include full string list in report | `false` |
| `--defang` | Defang IOCs in text/markdown | `false` |
| `--fail-on <low\|medium\|high\|critical>` | Exit 1 if any finding ≥ severity | — |
| `--min-string-len <N>` | Minimum string length | `4` |
| `--max-strings <N>` | Cap extracted strings | — |
| `--max-iocs <N>` | Cap IOC groups | — |
| `--max-scan-bytes <N>` | Cap bytes scanned | — |
| `--rules <FILE>` | Additional rule pack (repeatable) | — |
| `--no-default-rules` | Ignore embedded rule pack | `false` |

**Exit codes**: `0` ok, `1` `--fail-on` threshold met, `2` I/O/parse error, `4` config error.

---

### `info` — Normalized Structure Only

```bash
expe info [OPTIONS] <PATH>
```

| Option | Description | Default |
|--------|-------------|---------|
| `--format <text\|json\|markdown>` | Output format | `text` |
| `-o, --output <FILE>` | Write to file | — |
| `--rules <FILE>` | Additional rule pack | — |
| `--no-default-rules` | Ignore embedded rules | `false` |

Shows: format, arch, kind, entropy, sections, imports, exports, overlay, PDB, TLS, .NET, signature, Rich header, version info (PE); segments, sections, interpreter, libraries, rpath/runpath, build-id, symbols (ELF); segments, dylibs, entry (Mach-O).

---

### `strings` — Extract Strings

```bash
expe strings [OPTIONS] <PATH>
```

| Option | Description | Default |
|--------|-------------|---------|
| `--encoding <ascii\|utf16le\|both>` | Encoding to extract | `both` |
| `--min-len <N>` | Minimum string length | `4` |
| `--regex <PATTERN>` | Filter strings by regex | — |
| `--limit <N>` | Max strings to show | `200` |
| `--defang` | Defang output | `false` |
| `-o, --output <FILE>` | Write to file | — |

Output columns: `OFFSET  ENC  ×  STRING` (× = occurrences).

---

### `iocs` — Extract Indicators Only

```bash
expe iocs [OPTIONS] <PATH>
```

| Option | Description | Default |
|--------|-------------|---------|
| `--types <KIND1,KIND2,...>` | Comma-separated IOC kinds | all |
| `--defang` | Defang values in text/markdown | `false` |
| `--format <text\|json\|markdown>` | Output format | `text` |
| `-o, --output <FILE>` | Write to file | — |
| `--rules <FILE>` | Additional rule pack | — |
| `--no-default-rules` | Ignore embedded rules | `false` |

**IOC Kinds**: `ipv4`, `ipv6`, `domain`, `url`, `email`, `registry_key`, `windows_path`, `unix_path`, `mutex`, `named_pipe`, `pdb_path`, `bitcoin_address`, `ethereum_address`, `onion_address`, `embedded_pe`, `embedded_elf`.

---

### `batch` — Scan Many Files

```bash
expe batch [OPTIONS] <PATHS>...
```

| Option | Description | Default |
|--------|-------------|---------|
| `--recursive` | Recurse into directories | `false` |
| `--jobs <N>` | Worker threads (0 = auto) | `0` |
| `--format <text\|json\|jsonl>` | Output format | `text` |
| `-o, --output <FILE>` | Write to file | — |
| `--fail-fast` | Stop on first error/threshold | `false` |
| `--fail-on <low\|medium\|high\|critical>` | Exit 1 if any report ≥ severity | — |
| `--defang` | Defang in text output | `false` |
| `--rules <FILE>` | Additional rule pack | — |
| `--no-default-rules` | Ignore embedded rules | `false` |

**Text output**: one line per file:
```
ok    /bin/ls          ELF  x86_64  risk   0 low  findings 1  iocs 13
error /bad.bin         unsupported format
```

**JSON/JSONL**: array or lines of `{ "path": "...", "ok": true, "report": {...} }` or `{ "ok": false, "error": "..." }`.

**Exit codes**: `0` all ok, `1` `--fail-on` triggered, `2` any error, `4` config.

---

### `tui` — Interactive Terminal Console

```bash
expe tui [OPTIONS] [PATH]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--rules <FILE>` | Additional rule pack | — |
| `--no-default-rules` | Ignore embedded rules | `false` |

**If PATH omitted**: opens the path input screen.

**Requires TTY** (fails with helpful message if not).

#### TUI Keybindings

| Key | Action |
|-----|--------|
| `1`–`6` / `Tab` / `Shift+Tab` | Switch views |
| `↑` `↓` `j` `k` | Move selection |
| `PgUp` `PgDn` | Jump 10 |
| `Home` `End` | First / last |
| `/` | Live filter (Structure, Strings, IOCs, Findings) |
| `Enter` / `x` | Jump to hex at selected offset |
| `c` | Copy value/evidence (OSC52) |
| `d` | Toggle defanged IOC display |
| `e` | Export JSON report (`<stem>.expe.json`; adds `-1`, `-2`… instead of overwriting) |
| `r` | Re-analyze current sample |
| `o` | Open / change sample |
| `g` | Goto hex offset (Hex view) |
| `?` `F1` | Help overlay |
| `Esc` | Cancel / close overlay / back to Overview |
| `q` `Ctrl+C` | Quit |

#### TUI Screens

1. **Overview** — Risk gauge, KPI cards (format/entropy, findings, IOCs), top findings, section entropy bars, fingerprint (hashes, imphash, timing).
2. **Structure** — Sections table (name, VA, raw, entropy, perms) + metadata/imports panel.
3. **Strings** — Virtualized list with live regex filter, offset/encoding/occurrences/value.
4. **IOCs** — Grouped table (kind, value, confidence) + detail pane (value, scope, sources, offsets, rule).
5. **Findings** — Severity-sorted table + detail (evidence, ATT&CK).
6. **Hex** — 16/8/4 bytes/line, scroll, goto offset (`g`), mark highlight.

**Open** (via `o`) — File path input, analyzing spinner with stage progress.

---

### `rules` — Rule Pack Management

```bash
expe rules list [--file <FILE>]
expe rules check <FILE>
```

| Subcommand | Description |
|------------|-------------|
| `list [--file <FILE>]` | List default + optional user pack (id, kind, severity, confidence, validator) |
| `check <FILE>` | Validate rule pack, report version and rule count |

**Rule TOML format**:
```toml
version = "1.0.0"
[[rules]]
id = "ioc.custom_domain"
kind = "domain"
severity = "medium"
confidence = "high"
pattern = "custom\\.example\\.com"
validator = "domain"
```

---

### `schema` — JSON Schema

```bash
expe schema
```
Prints JSON Schema for `AnalysisReport` (schemars/draft-07).

---

## Output Formats

### Text (Default)
Human-readable tables with Unicode borders. Respects `NO_COLOR` (disables colors) and `EXPE_ASCII` (ASCII-only borders/icons).

### JSON
Deterministic ordering, `schema_version`, all fields. Suitable for piping to `jq`.

### Markdown
GitHub-flavored tables for reports, findings, IOCs.

### JSONL (Batch Only)
One JSON object per line for streaming.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | `--fail-on` threshold reached (analyze/batch) |
| `2` | I/O error, parse error, unsupported format |
| `4` | Config error (bad args, rule load, etc.) |

---

## Environment Variables

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Disable all colors in CLI/TUI output |
| `EXPE_ASCII` | Use ASCII-only borders/icons in TUI |
| `TERM=dumb` | TUI refuses to start (use CLI instead) |

---

## Rule Pack Structure

Embedded default: `crates/expe-engine/rules/default.toml` (14 rules).

User packs can override by `id`. Merge order: default → user files in order given.

Each rule:
- `id`: unique string
- `kind`: one of 17 `IocKind` values
- `severity`: `info`/`low`/`medium`/`high`/`critical`
- `confidence`: `low`/`medium`/`high`
- `pattern`: regex (candidate pass)
- `validator`: one of `ipv4`, `ipv6`, `domain`, `url`, `email`, `path`, `bitcoin`, `ethereum`, `onion`, `generic`

---

## Risk Scoring Algorithm

```
For each finding:
  weight = {info:0, low:2, medium:6, high:12, critical:20}[severity]
  accumulate per Category (12 categories)

For each category:
  capped = min(points, 25)

raw = sum(capped)
score = round(100 * (1 - exp(-raw / 40)))

Verdict:
  0–14      → Low
  15–39     → Elevated
  40–69     → Suspicious
  70–100    → High
```

---

## Safety Guarantees

- **No execution** — samples are only read, never run
- **Read-only** — regular files only, size caps enforced
- **Panic isolation** — third-party parsers run in isolated contexts
- **Terminal sanitization** — all sample-originated text stripped of ESC/CSI/OSC/bidi/NUL before output
- **No network** — fully offline operation

---

## Common Workflows

### Triage a Suspicious File
```bash
expe analyze malware.bin --format json | jq '.risk, .findings[] | select(.severity != "info")'
```

### Bulk Scan with Threshold
```bash
expe batch ./samples --recursive --fail-on high --format jsonl -o results.jsonl
# Exit 1 if any sample has High findings
```

### Extract C2 Infrastructure
```bash
expe iocs sample.bin --types domain,url,ipv4,ipv6 --format json | jq '.iocs[].items[].value'
```

### Interactive Investigation
```bash
expe tui sample.bin
# Navigate: 1=Overview, 2=Structure, 3=Strings, 4=IOCs, 5=Findings, 6=Hex
# Filter with /, jump to hex with Enter/x, copy with c, export with e
```

### Custom Rules for Organization
```bash
# Create org-rules.toml with internal IOC patterns
expe analyze sample.bin --rules org-rules.toml
expe rules check org-rules.toml
```

---

## Performance Notes

- **Streaming hashes** — single pass read for MD5/SHA1/SHA256
- **RegexSet** — single pass over strings for all IOC patterns
- **Parallel batch** — `--jobs N` uses rayon thread pool
- **String caps** — `--max-strings`, `--max-scan-bytes` prevent OOM
- **TUI** — background worker, UI stays responsive during analysis

---

## Project Structure (for Contributors)

```
crates/
  expe-core/       # Domain models, ports, scoring, error taxonomy
  expe-engine/     # Parsers, entropy, strings, IOCs, heuristics, analyzer
  expe-tui/        # MVU app, screens, worker, theme, sanitize
  expe-cli/        # Clap commands, output formatters
  expe-testkit/    # Synthetic PE fixtures for tests
```

---

## Version & Compatibility

- **Rust**: 1.88+ (MSRV), edition 2024
- **Schema**: `1.0` (in `schema_version` field)
- **Ruleset**: `1.0.0` (in `tool.ruleset_version`)

---

## License

MIT OR Apache-2.0