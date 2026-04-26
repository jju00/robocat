# CVE Form Writing Guide (Request Type: Report Vulnerability / Request CVE ID)

This document defines how to fill `https://cveform.mitre.org/` sections when `Report Vulnerability/Request CVE ID` is selected, using only `strict_results` from `results/{target}.md`.

## 0) Language Rule (Mandatory)
- Write all report content in English.
- Fill all CVE form text fields in English.

## 0.1) Report Format Rule (Mandatory)
- The final report file must be written as raw plain text for direct website form input.
- Do not use Markdown formatting in the report output (no headings with `#`, no tables, no fenced code blocks, no bullet markdown syntax).
- Use simple section labels and plain line breaks only.

## 1) Data Source Rules (Mandatory)
- Use only `strict_results` from `results/{target}.md`.
- Do not use or cite `broad_results` as evidence.
- Do not add speculative claims that are not supported by strict evidence.
- Report content must include only `strict_results` items with `status=confirmed`.
- Do not include `rejected` strict items, broad candidates, or non-strict summary tables in the final report.

## 1.1) AGENTS.md Rejection Criteria (Mandatory)
- In `strict`, if the trigger is reachable only through `examples/`, `samples/`, `benchmarks/`, or `tests/`, do not treat it as valid impact.
- Reproduction using only PoC harness/test code is not enough to claim real user impact.
- Impact/Description must be based on production/real-world code paths.
- If this condition is not met, exclude from CVE draft or clearly mark limitations in `Additional information`.

## 2) Section-by-Section Writing Rules
- Enter your e-mail address
  - robocat135@gmail.com

- Number of vulnerabilities reported or IDs requested (1-10)
  - Use the count of `status=confirmed` findings in `strict_results`.
  - Max 10 per request.

- Do you need more than 10 IDs?
  - `Yes` if strict confirmed findings > 10, otherwise `No`.

- Vulnerability type
  - Select based on each strict finding memory-corruption type.
  - Examples: Buffer Overflow, Use After Free, Double Free, Integer Overflow.

- Vendor of the product(s)
  - Use the actual impacted vendor/maintainer from strict evidence.

- Affected product(s)/code base
  - Product: impacted software/library name.
  - Version: only evidence-backed affected version/range.

- Has vendor confirmed or acknowledged the vulnerability? (Yes/No)
  - `Yes` only with evidence (advisory, maintainer response, issue confirmation).
  - Otherwise `No`.

- Attack type
  - Select from strict evidence: Remote / Local / Physical / Context-dependent.

- Impact
  - Select actual outcome from strict evidence:
  - Code Execution / Information Disclosure / Denial of Service / Escalation of Privileges / Other
  - Must reflect real user application impact (not examples/tests-only paths).

- Affected component(s)
  - Provide exact component path/function from strict findings.
  - Format: `path::function`.

- Attack vector(s)
  - Write this section as a concise summary within 800 characters.
  - Even within 800 characters, include the core code-reversing flow:
  - external input entry point -> parsing/validation gap -> source-to-sink path -> memory-corruption sink.
  - Include only strict-validated paths.
  - Put full reproduction details in Section B (do not overload Section A).

- Suggested description of the vulnerability for use in the CVE
  - Write one single NVD/NIST-style sentence.
  - Style example: "A stored Cross-Site Scripting (XSS) vulnerability exists in the port forwarding page ..."
  - Include: affected product/version + vulnerable component/page/function + vulnerability type + trigger condition.
  - No exaggeration; strict evidence only.
  - Do not rely on harness/test-only trigger as primary evidence.
  - Keep detailed evidence and code snippets in Section B, not in this one-line description.

- Discoverer(s)/Credits
  - Enter robocat

- Reference(s)
  - Use public URLs only (issue, commit, advisory, repro write-up).
  - If only internal paths exist, minimize references until public evidence is available.

- Additional information
  - Add prerequisites, exploit constraints, mitigation status.
  - Strict-validated facts only.
  - If repro depends on tests/examples, explicitly state limitation and separate from production path evidence.

## 3) Multiple Findings Handling
- If there are multiple strict confirmed findings, document each clearly.
- If they share the same root cause, they may be grouped as one CVE candidate only when component/impact boundaries are still explicit.
- If there are zero strict confirmed findings, write a short strict-only conclusion and do not add candidate/rejected details.

## 4) Writing Template
Use this template per vulnerability.

```text
[Request Type]
Report Vulnerability/Request CVE ID

Enter your e-mail address:
- <email>

Number of vulnerabilities reported or IDs requested (1-10):
- <strict_confirmed_count>
Do you need more than 10 IDs?
- <Yes|No>

Vulnerability type:
- <type>

Vendor of the product(s):
- <vendor>

Affected product(s)/code base:
- Product: <product>
- Version: <affected_versions>

Has vendor confirmed or acknowledged the vulnerability?
- <Yes|No>

Attack type:
- <Remote|Local|Physical|Context-dependent>

Impact:
- <Code Execution|Information Disclosure|Denial of Service|Escalation of Privileges|Other>

Affected component(s):
- <path::function>

Attack vector(s):
- <detailed source-to-sink trigger path + repro summary>

Suggested description of the vulnerability for use in the CVE:
- <CVE-style description based on strict evidence>

Discoverer(s)/Credits:
- <name or N/A>

Reference(s):
- <url1>
- <url2>

Additional information:
- <constraints/repro notes/mitigation status>
```

Report structure requirement (raw text):
- Section A: CVE form-ready raw text content only.
- Section B: Separate PoC reproduction notes for Notion paste, placed below Section A.
- Section B must be clearly labeled, but still plain text (no markdown syntax).

## 5) Prohibited Practices
- Do not present broad candidates as strict findings.
- Do not claim exploitation without evidence.
- Avoid speculative wording (`likely`, `may`) unless clearly scoped in `Additional information`.
- Do not present examples/tests-only reachability as real-world impact.
- Do not include rejected findings in report summary tables or CVE draft sections.

## 6) Report Output Path Rule
- Always write the report to `results/<target_name>_report.md`.
- Example: target `libpng` -> `results/libpng_report.md`.
- Reproduction artifacts must be actually created on disk under:
  - `/home/nagoX/bugbounty/nuclei/targets/<target_name>/`
- Create the target directory if missing.
- Save practical files needed for reproduction, such as:
  - PoC generator scripts
  - PoC input files (sample payloads, crafted files, request bodies)
  - Crash evidence files (logs, stderr/stdout captures, sanitizer outputs, crash traces)
- Section B must reference the exact artifact file paths created in that directory.
- If Section B includes any step that executes, reads, or writes a file, that file must exist in `/home/nagoX/bugbounty/nuclei/targets/<target_name>/`.
- If a required file does not exist, create it directly or provide a file-generation script, and place that script in the same target directory.
- If reproduction requires a built binary, Section B must include explicit build commands.
- Build commands must be derived from actual build files under `/home/nagoX/bugbounty/nuclei/targets/<target_name>/source` (for example: `Makefile`, `CMakeLists.txt`, `configure.ac`, build scripts).
- Section B must include:
  - source directory used for build,
  - exact build command sequence,
  - output binary path used in reproduction.

## 7) Reproduction Documentation Rule (Strict, Mandatory)
- The report must document only real runtime reproduction on actual service/product code paths.
- Do not include any NLD execution process in the report.
- Do not include NLD tool names, query logs, or NLD intermediate outputs in Section A or Section B.
- NLD is internal analysis support performed by Claude only; it is not part of reportable reproduction.
- Reproduction content must include:
  - environment,
  - payload/input,
  - exact commands/requests,
  - step-by-step trigger sequence,
  - crash/memory-corruption evidence from real execution,
  - success/failure verdict and failure cause (if failed).
- The PoC reproduction details must be in Section B (Notion-paste plain text), focused on real service crash/trigger steps only.

## 8) Code Snippet Inclusion Rule (Mandatory)
- Include real code snippets for all critical points; summary-only writing is not allowed.
- Minimum snippet coverage:
- Source entry code
- Validation/guard code (or absence)
- Sink (memory operation) code
- Core code along the actually traversed call chain
- Every snippet must include `file_path:line`.
- Keep snippets focused and short; avoid dumping large unrelated code blocks.
