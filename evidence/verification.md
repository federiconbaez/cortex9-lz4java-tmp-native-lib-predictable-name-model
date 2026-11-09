# Verification before building (CVE-2026-106451)

This repo replaces an earlier candidate. Before building, the CVE ID, the
fix commit and the fixed version were checked against primary sources.
Copies of the saved sources are in `sources/` with `sources/SHA256SUMS`;
they are byte-identical to `security-research-45/sources/cve2026/`.

| Check | Source | Result |
|---|---|---|
| The CVE exists | `sources/nvd_CVE-2026-106451.json` (NVD, status Awaiting Analysis) | references the fix commit, tag `v1.11.4` and GHSA-mcr4-qmvw-px4g |
| Advisory, versions, CWE | `sources/ghsa_CVE-2026-106451.json` (GHSA-mcr4-qmvw-px4g, published 2026-10-07T20:35:51Z, high) | `at.yawk.lz4:lz4-java` `<= 1.11.3`, patched `1.11.4`; `org.lz4:lz4-java` `>= 1.7.0, <= 1.8.1`, no patched version; CWE-367, CWE-377; introduced in c3ddae5 (lz4-java 1.7.0) per the advisory |
| Fix commit and lines | `sources/CVE-2026-106451_lz4-java_7a48b7f6b809.diff` (commit 7a48b7f6b8099b9dab6541e4ac2ee0979dc55aa3, "Merge commit from fork", 2026-09-25T17:57:09Z) | `Native.java` L47-48 (pre) and L51 (post); cleanup L9-10, L25-26, L32-35; `NativeTest` L186-216 |
| Fix is in 1.11.4 | GitHub API `compare/7a48b7f6b8099b9dab6541e4ac2ee0979dc55aa3...v1.11.4`, read-only, 2026-11-09 (ART); raw response sha256 ac98f163ddb4403f90db6870158dbf2a39b3a8630130f7d67762de84dacd212d | `ahead` 1 / behind 0, merge base 7a48b7f; the one commit is 4af910bc99c2f021f0cd56f6ca7f7600f4dda4a0 (2026-09-25T18:07:15Z) |
| Fix is not in 1.11.3 | GitHub API `compare/v1.11.3...7a48b7f6b8099b9dab6541e4ac2ee0979dc55aa3`, read-only, 2026-11-09 (ART); raw response sha256 27e1364726857903aba23e6ca6d41737754ec9210fa12f95e927b068920dbceb | `ahead` 28 / behind 0 |

The raw API responses are not committed because they contain upstream
committer e-mail addresses. The NVD record is committed verbatim; it
contains the CNA identifier `security-advisories@github.com`, an
organisational address, kept so the file matches its SHA-256.

Not verified: commit c3ddae5 itself (named only in the GHSA) and the
`org.lz4:lz4-java` range.

No source contained instructions addressed to a tool or agent (grep for
injection phrases and invisible Unicode over all five files).
