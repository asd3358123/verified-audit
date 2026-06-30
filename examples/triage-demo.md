# Triage demo — verified-triage over gosec, on a public repo

A reproducible run of the [`--sarif` triage mode](../tool/README.md#two-modes) over [**ffuf**](https://github.com/ffuf/ffuf) (a popular open-source Go web fuzzer), at commit `57da720` (2025-04-24). Public repo, so these numbers are free to cite.

## Reproduce

```bash
git clone https://github.com/ffuf/ffuf && cd ffuf
go install github.com/securego/gosec/v2/cmd/gosec@v2.27.1
gosec -severity medium -confidence medium -no-fail -fmt sarif -out gosec.sarif ./...
go install golang.org/x/tools/cmd/deadcode@v0.47.0
OPENROUTER_API_KEY=... python /path/to/tool/verified_audit.py --repo . --sarif gosec.sarif --out triage.md
```

## Result

gosec raised **25** findings. verified-triage:

| | count |
|---|---|
| confirmed (kept) | 9 |
| **refuted (false positives killed)** | **16 (64%)** |
| inconclusive (verify failed → surfaced, not cleared) | 0 |

### Refuted — the noise, killed with the reason a human would give

These are the classic context-free SAST false positives:

- **`util.go:19` — G404 (weak random):** *"math/rand is used to generate auto-calibration probe URLs… no tokens, no session IDs, no secrets, no key material. The unpredictability is irrelevant to the tool's security model. A false positive from a blanket rule without semantic context."*
- **`stdout.go:361` — G401 (MD5):** *"MD5 is used purely as a non-cryptographic file-naming mechanism (a content-addressable filename). No security property is claimed; the weakness of MD5 is irrelevant when it only derives a filename."*
- **`scraper.go:37` — G304 (file path):** *"the filename comes from `os.ReadDir` of a fixed, trusted local directory (a constant), not an external/untrusted attacker."*

G304 (file-path) was by far the largest gosec category — almost all of it is ffuf reading its own wordlists/config by path, and the triage refuted it with that reasoning.

### Confirmed — kept, and honestly severity-rated

| severity | rule | location |
|---|---|---|
| HIGH | G204 | `pkg/input/command.go:71` |
| MEDIUM | G402 | `pkg/runner/simple.go:71` (TLS `InsecureSkipVerify`) |
| LOW | G404 | `pkg/ffuf/job.go:198` |
| LOW | G302 ×2 | `pkg/output/audit.go:17`, `main.go:206` (file perms) |
| LOW | G306 ×4 | output/file writers (file perms) |

It does **not** inflate severity — six of the nine confirmed are file-permission issues, correctly rated LOW.

### A note on the one HIGH (transparency)

The HIGH (`command.go:71`, G204) is ffuf's `-input-cmd` feature, which `exec`s a user-supplied command. The verifier confirmed it but **reasoned about the threat model explicitly**:

> *"while this is a CLI tool where the user runs it themselves, the concern is valid in contexts like web interfaces, CI/CD pipelines, or wrapper scripts that pass user-controlled input to ffuf's `-input-cmd`."*

Reasonable people can disagree on whether that's a vulnerability or an intended feature — which is exactly the point: **the tool narrows 25 alerts to 9 candidates with explicit reasons; a human still arbitrates the threat model.** A confirmed severity is provisional (see [METHODOLOGY.md](../METHODOLOGY.md) → "source, not just sink").

## Caveats

- One run on `anthropic/claude-sonnet-4.6`; numbers vary run to run.
- This triages what *gosec* reported — it refutes gosec's false positives, it does not find what gosec missed (for that, use audit mode).
