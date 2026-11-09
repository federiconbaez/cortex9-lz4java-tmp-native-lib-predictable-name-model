# Sources

Copies in `sources/` (checked by `sources/SHA256SUMS` and in CI),
byte-identical to `security-research-45/sources/cve2026/`. `Lnnn` are
`cat -n` line numbers of the diff file.

| File | URL | Used for | SHA-256 |
|---|---|---|---|
| `CVE-2026-106451_lz4-java_7a48b7f6b809.diff`, commit 7a48b7f6b8099b9dab6541e4ac2ee0979dc55aa3 (2026-09-25) | https://github.com/yawkat/lz4-java/commit/7a48b7f6b8099b9dab6541e4ac2ee0979dc55aa3 | pre L47-48, L53, L56; post L51; cleanup L9-10, L25-26, L32-35; NativeTest L186-216 | 7ad67de231e5e596afcd85041fda1f3e073c1f3e911a8adbe4c597240856a48b |
| `ghsa_CVE-2026-106451.json`, GHSA-mcr4-qmvw-px4g | https://github.com/yawkat/lz4-java/security/advisories/GHSA-mcr4-qmvw-px4g | versions, CWE, host conditions (sysctls, sticky bit, private tmpdir), Java fallback | f1c6145cfd4bbf430b99e00904f1a7720938a586a31243885f76e59fcbe569db |
| `nvd_CVE-2026-106451.json` (Awaiting Analysis) | https://nvd.nist.gov/vuln/detail/CVE-2026-106451 | the CVE ID exists and points to the commit, tag and GHSA | 6eeeeb96d052c03098da709dc420d070bad93ddc19db61e8f8f0cead3031dc37 |
| Compare API, read-only, 2026-11-09 | https://github.com/yawkat/lz4-java/compare/v1.11.3...v1.11.4 | fix in 1.11.4 and not in 1.11.3: `evidence/verification.md` | see that file |

The upstream diff is Apache-2.0 (header at L160-174). No source contained
instructions addressed to a tool or agent.
