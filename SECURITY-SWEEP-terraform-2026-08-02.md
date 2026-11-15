<!-- verified-against: 2026-08-02 cdcb405af74cbb67fd4aa45fb4070a4573ac45ab -->
# terraform — containerised commitwork security sweep

_Anchor: `cdcb405af74cbb67fd4aa45fb4070a4573ac45ab` (`main`, committed 2026-07-31T14:28:42+01:00,
"command/state-migrate: Implement support for upgrades (#38908)"). Every count below was measured at
that SHA. A claim without a SHA is not a claim._

**Nothing in this sweep executed repository code.** No `go build` of the target ran as part of
analysis, no test suite was invoked, no network service was started, no credential was used. Both
passes ran inside a throwaway Docker container with the repository cloned *inside* it; the commitwork
checkout was mounted read-only. The only build performed was a compile-check of this branch's own
one-line change, run in the same container.

## What this sweep is allowed to say

Two passes ran. The first is commitwork's `security-baseline` manifest as it ships. The second exists
because the first was **wrong about its own coverage**, and that is the sweep's most important
result.

Terraform is a Go repository — 1.0 million lines of it across **11 nested `go.mod` modules**.
Pass 1 ran with no Go toolchain in the image. Under those conditions:

- `osv-scanner` printed `Skipping call analysis on Go code since Go is not installed` **11 times**
  (once per module) and still exited 0. Its reachability lane was off. The report did not say so.
- commitwork's two deep-taint checks are `sast-codeql` (`--language=javascript-typescript`) and
  `sast-codeql-java` (`--language=java`). **Neither covers Go.** Both were correctly reported as
  `blocked` for missing the CodeQL CLI — which masked the real problem: even fully equipped, this
  manifest has no taint lane that could analyse this repository at all.
- Every npm-shaped supply-chain check (`npm-audit`, `deps-retire`, `sbom` via cyclonedx-npm,
  `supply-chain-guarddog`, `supply-chain-socket`) is inapplicable to a Go module graph. The Go
  supply chain was scanned by **no supply-chain-specific tool** in pass 1.

So pass 1's clean-looking result was, in the fleet's own vocabulary, **grey — not green**. Pass 2
added Go 1.26.5 (terraform's `go.mod` declares `go 1.26.4`; anything older cannot even load the
module graph), `govulncheck`, `gosec`, `grype`, `hadolint`, and a coverage ledger in which every lane
must record either a result count or a reason it did not run.

### Coverage ledger

| lane | state | result |
|---|---|---|
| trufflehog (git history) | RAN | 0 verified, 0 unverified across 6,661 chunks / 24.7 MB |
| gitleaks (filesystem) | RAN | 93 raw → **0 real** after triage |
| semgrep (1,074 rules) | RAN | 114 raw → 32 error-level → **2 real** |
| trivy config | RAN | 1,163 raw → **5 real** (1,150 are terraform's own `testdata/*.tf`) |
| syft SBOM | RAN | 1,040 components |
| stub-detect | RAN | 902 markers (hygiene, not vulns) |
| govulncheck (symbol) | RAN | 1 advisory, **0 reachable** |
| gosec | RAN | 756 raw → 412 `G104` unchecked-error → **1 acted on** |
| osv-scanner (with Go) | RAN | 1 advisory (`GO-2026-5932`), 0 call-analysis skips |
| grype | RAN | 11 matches — all the same `GO-2026-5932` across 11 `go.mod` files |
| hadolint | RAN | 1 finding — **but see the scanner defect below** |
| **codeql-go** | **NOT-RUN** | CodeQL bundle is x86_64; failed under Rosetta on arm64: `rosetta error: failed to open elf at /lib64/ld-linux-x86-64.so.2`. **This is the deepest lane and it did not run. Its absence is a hole, not a pass.** |
| **staticcheck** | **NOT-RUN** | exited with empty stdout *and* empty stderr. My harness recorded no reason, so I cannot tell you why. Recorded as an unexplained void rather than dressed up as a clean result. |
| npm-audit · deps-retire · cyclonedx-npm · guarddog · socket | NOT-RUN | npm-only; repo is Go. **Go supply-chain provenance is uncovered.** |
| sast-codeql (js-ts) · sast-codeql-java | NOT-RUN | wrong language for this repo |
| nuclei · authz-bola · testssl · schemathesis | NOT-RUN | runtime scanners; terraform is a CLI with no server surface |
| deps-updates (renovate) | NOT-RUN | needs docker-in-docker |

## Confirmed findings

**1 — SSH provisioner does not verify host keys unless `host_key` is set.**
`internal/communicator/ssh/provisioner.go:330` — `hkCallback := ssh.InsecureIgnoreHostKey()` is the
default; a `knownhosts` CA callback is built only when `opts.hostKey != ""`. Found independently by
semgrep (`avoid-ssh-insecure-ignore-host-key`) and gosec (`G106`). Any `remote-exec`/`file`
provisioner run without an explicit `host_key` is open to an active man-in-the-middle, and that is
the connection over which provisioner payloads and often credentials travel. This is long-standing
documented behaviour rather than a regression, which is why it is reported and **not** patched here:
changing the default is a breaking change for every existing configuration and belongs to the
maintainers. **Not fixed in this branch. Proposal only.**

**2 — Temporary OAuth callback server has no header-read deadline.**
`internal/command/login.go:419` (gosec `G112`). `terraform login` starts an `http.Server` on
localhost to receive the OAuth redirect. With no `ReadHeaderTimeout`, a connection that dribbles
headers holds the goroutine until the operator interrupts. Localhost-bound, ephemeral, and
low-severity — but the fix is one field and cannot alter behaviour, because the real callback is a
same-machine redirect that arrives immediately. **Fixed in this branch.**

**3 — Dependabot has no cooldown window.**
`.github/dependabot.yml` (semgrep `dependabot-missing-cooldown`, both ecosystems). Without a
cooldown, a compromised or yanked publish can be adopted inside the window in which it is most
likely to be caught. GitHub exempts security updates from cooldown, so advisory-driven bumps are not
delayed. **Fixed in this branch** (`default-days: 7` on both `gomod` and `github-actions`).

**4 — Release container image runs as root, base image unpinned.**
`build.Dockerfile` — trivy `DS-0002` (no `USER`), `DS-0026` (no `HEALTHCHECK`), `DS-0001`
(`alpine:latest`, line 13). This is the image published to the `terraform` Docker namespace. Adding a
non-root `USER` is defensible hardening but changes the runtime contract for anyone mounting
host-owned state or plugin directories, so it is **proposed, not applied**. `HEALTHCHECK` is
meaningless for a CLI entrypoint and is dismissed. Pinning the base image by digest is the
highest-value item of the three.

## Refuted findings

Recorded rather than deleted, because a refutation that took real work is worth as much as a finding.

- **SQL injection in the Postgres backend — REFUTED.** semgrep `gosql-sqli`, 3 hits at
  `internal/backend/remote-state/pg/backend.go:119,135,142`. All three interpolate `b.schemaName`
  into DDL, and line 95 sets `b.schemaName = pq.QuoteIdentifier(data.String("schema_name"))`. SQL
  identifiers cannot be bound as parameters; `QuoteIdentifier` is the correct control. Correct code.
- **Insecure gRPC server — REFUTED.** `internal/rpcapi/internal_client.go:48`. The listener is
  `bufconn.Listen`, an in-memory pipe used so Terraform CLI can call Terraform Core without forking.
  There is no socket, so there is no transport to encrypt.
- **`GO-2026-5932` (`x/crypto/openpgp` unmaintained) — REFUTED as unreachable.** Reported by
  osv-scanner (×11), grype (×11) and govulncheck. `govulncheck` returned it with a module-level trace
  and **no call stack**, and no file in the tree imports `golang.org/x/crypto/openpgp` — terraform
  already uses `github.com/ProtonMail/go-crypto v1.1.3`, the maintained fork, in
  `internal/getproviders/` and `internal/releaseauth/`. The advisory has no fixed version, so it will
  be reported forever by any module-level scanner. **This is the entire dependency-vulnerability
  result: one advisory, already mitigated.**
- **26 weak-crypto (MD5) hits — REFUTED.** Content checksums for object-storage protocols
  (S3/OSS/COS/OCI `Content-MD5`, TFE state MD5). Protocol-mandated, not security hashing.
- **`crypto/sha1` and `crypto/md5` imports in `internal/lang/funcs/crypto.go` — REFUTED.** These
  implement terraform's own `sha1()` and `md5()` language functions. Removing them removes language
  features.
- **`InsecureSkipVerify` in the http backend — REFUTED.**
  `internal/backend/remote-state/http/backend.go:288` is reached only when the operator sets
  `skip_cert_verification`. Opt-in, documented.
- **93 gitleaks hits — 0 real.** 69 are in `testing/equivalence-tests/` golden files (deliberate
  fixture values in recorded state/plan output), 24 in test fixtures, and the single hit outside test
  paths is `internal/legacy/helper/schema/resource_timeout.go:16` —
  `TimeoutKey = "e2bfb730-ecaa-11e6-8f88-34363bc7c4c0"`, a UUID sentinel constant. Corroborated by
  trufflehog finding **zero** verified or unverified secrets across the full git history.
- **1,150 of 1,163 trivy findings — dismissed as corpus.** `AWS-0131` and `AWS-0028` fire 563 times
  each inside `internal/terraform/testdata/` and `internal/configs/testdata/`. Scanning a Terraform
  implementation's own `.tf` test corpus for Terraform misconfigurations measures nothing.
- **8 `dangerous-exec-command` / 11 gosec `G204` — by design.** Terraform launches provider plugins
  and the `local-exec` provisioner. Executing operator-authored commands is the documented feature.

## Defects in the scanner, not the subject

**A — `dockerfile-lint` cannot see `build.Dockerfile`.** The check globs
`find . -name 'Dockerfile*'`, which matches `Dockerfile` but **not** `build.Dockerfile`. In this
repository that means hadolint linted the development-convenience image and skipped **the image that
is actually published**, while reporting `RAN` with a finding count. A prefix glob cannot see the
`<purpose>.Dockerfile` convention. It should be `-name 'Dockerfile*' -o -name '*.Dockerfile'`.
Trivy caught `build.Dockerfile` only because it discovers Dockerfiles by content.

**B — no Go lane exists.** `security-baseline` has CodeQL lanes for JavaScript/TypeScript and Java
and none for Go, plus five npm-only supply-chain checks and zero Go equivalents. Against a Go
repository the manifest's deep and supply-chain groups are structurally empty, and nothing in the
output says so. `gosec` and `govulncheck` should be first-class checks with
`appliesIfExists: ["go.mod"]`.

**C — degraded is not distinguished from clean.** osv-scanner exits 0 and prints its
`Skipping call analysis` notice to stderr, which the manifest redirects to a `.log` nobody parses.
A scanner that ran with a lane disabled must not be recorded identically to one that ran whole.

**D — my own harness reproduced the pathology.** The pass-2 image build failed (Go 1.24.5 could not
install `govulncheck`, which requires ≥1.25), and my wrapper's `|| (echo BUILD_FAIL; …)` swallowed
the non-zero exit, so the orchestration recorded exit 0. The failure surfaced only because the next
step could not find the image. This is the same defect class as **C**, committed by the tool that was
auditing for it, and it is recorded here for the same reason the refutations are.

## What changed in this branch

| file | change | finding |
|---|---|---|
| `internal/command/login.go` | add `ReadHeaderTimeout: 10 * time.Second` to the login callback server (+ `time` import) | gosec `G112` |
| `.github/dependabot.yml` | add `cooldown: default-days: 7` to both ecosystems | semgrep `dependabot-missing-cooldown` |

Both are behaviour-preserving. `go build ./internal/command/` and `go vet ./internal/command/` were
run against the modified tree in the scanner container.

## Honest summary

Terraform at `cdcb405` is in good security condition. Across roughly 3,000 raw scanner outputs from
nine tools, **zero secrets**, **zero reachable dependency vulnerabilities**, and **four real
findings** survived triage — of which one is a documented product default, one is a container
packaging choice, and two were fixable in eleven lines. The raw counts are dominated by a test corpus
that a naive report would have presented as 1,163 misconfigurations.

The finding with the longest tail is not in terraform. It is that a scanner manifest built around
npm and JVM ecosystems produced a clean-looking report for a million-line Go codebase whose deepest
analysis lane never existed, and that neither the exit codes nor the report said so. The subject
passed. The instrument needed the second pass to know whether it was entitled to say that.
