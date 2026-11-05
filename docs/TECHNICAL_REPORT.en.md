# AgentSupplyGuard: Public Evidence and Policy Actions for Python Dependency Changes

**Technical report — English edition, 5 November 2026**

This report consolidates existing AgentSupplyGuard research artifacts and subsequent analyses. It is a prepublication technical record, not a peer-reviewed publication or a validation of a deployed security product. Final author and contributor attribution must be confirmed before public release. The research sources identify Hyunsoo Lee and Geunseok Yang; the original license uses the spelling Hyeonsu Lee. Those records are preserved rather than silently reconciled. A course-project team roster is not substituted for research authorship.

## Abstract

Functional tests and dependency security answer different questions. This report documents how archived public records support assessments of Python dependency changes attributed to AI coding agents, how reporting rules affect uncertainty, and how a policy converts signals into warnings or blocks. In an existing corpus of 8,752 dependency additions and version changes from 1,101 pull requests, 279 changes match specified public-record criteria. On the same 5,790 non-exact declarations, two reporting procedures produce 1,844 and 503 UNKNOWN outcomes. Their supported scopes and completeness rules differ, so this change is reporting sensitivity, not independently measured accuracy improvement. In a separate retained subset, the full policy blocks 169, warns on 105, and passes four of 278 reference-positive changes. A historical batch execution reproduced five fixed policy scenarios against saved outputs. Follow-up analyses examined finite release-date uncertainty and positive evidence within unresolved assessments. However, all 339 selected positive witnesses in the residual UNKNOWN subset were already present in existing scanner details, and a baseline given the same information reproduced the candidate's positive outputs. The report therefore preserves descriptive findings, reproducibility evidence, negative results, and limitations without claiming a new detection advantage, installed safety, or demonstrated reviewer benefit.

## 1. Purpose and research questions

A coding agent may edit dependency manifests such as `requirements.txt` and `pyproject.toml` while implementing a feature. Passing functional tests does not establish that a package exists, that a requested version was released, that a version has no applicable public advisory, or that installation respects an organization's permissions and license rules. A public advisory is a recorded vulnerability description; a match to that record is not evidence that a particular installation is exploitable.

This report addresses three questions:

1. What can be assessed from the retained records under explicit support and completeness requirements?
2. How much do reported states change when those requirements change on a fixed declaration frame?
3. How does a policy translate signals into actions, and which stronger claims remain unsupported?

The report does not estimate excess risk over human-authored changes, independently validated detection accuracy, live attack prevention, or reductions in human review time. Results described below come from existing research and follow-up artifacts. Preparing this English report did not rerun models, scanners, or policy evaluators. [R1–R8]

## 2. Assessment, evidence, and action

The analysis separates three outputs. A **reference label** records whether a change meets a specified public-record criterion. An **assessment** answers a particular question about a declaration under stated support and completeness rules. A **policy action** determines whether to pass, warn, or block. These outputs need not agree because they have different scopes.

| Term | Meaning in this report | What it does not establish |
|---|---|---|
| Public-record criterion match | A match to a defined package-absence, invalid-exact-version, or advisory criterion | Actual installation, execution, or exploitability |
| Assessability | Whether the available input supports a determinate answer to a specified question | Overall safety |
| PASS | No warning or blocking condition fired in the applied policy | Safety against every threat |
| WARN | The policy requests attention or review | Successful prevention |
| BLOCK | The policy returns a blocking decision | Prevention of an already executed installation |
| UNKNOWN | Evidence or supported interpretation is insufficient for the question | A safe negative, or a proven vulnerable installation |
| Replay | Recalculation using fixed code, inputs, and policy | Correctness of the original evidence or reference labels |

Raw evidence and supported evidence also differ. A **raw match** is a match reported before all support requirements are applied. A **supported witness** is a specific allowed release token and advisory match accepted under the stated support requirements. Neither term means that a resolver selected or installed that version.

UNKNOWN is a state of the assessment analysis, not a universal return value of every implementation path. For example, a strict S1 configuration can raise an error when evidence is missing. License-policy violations are separate from security-vulnerability criteria. Counting all policy interventions as successful vulnerability detections would mix these constructs. [R1, R7]

## 3. Threat model and implementation

The relevant assets include source and manifest integrity, build artifacts, accessible data and credentials, and execution resources. Trust boundaries occur between agent-proposed names and versions, parsed dependency declarations, external metadata, and the environment that installs and executes packages. These boundaries motivate input validation, isolation, least privilege, and audit records. Their importance as design principles is distinct from evidence that this implementation provides those protections.

The retained guard has six stages:

| Stage | Check | Scope limitation |
|---|---|---|
| S1 | Package existence | Present registry absence does not reconstruct every historical deletion or prove hallucination |
| S2 | Version validity | Exact pins and version ranges require different questions |
| S3 | Direct dependency advisories | Matching depends on package, version, coordinate, dates, and supported representation |
| S4 | Transitive dependency advisories | Conclusions depend on the retained dependency relationships |
| S5 | License policy | A license violation is not itself a security vulnerability |
| S6 | Dependency restraint | Conclusions depend on explicit policy, such as a dependency-free task requirement |

Relevant source files include `pipeline/dep_extractor.py`, `pipeline/guard/decision.py`, the six stage modules, `pipeline/run_task.py`, and `pipeline/test_runner.py`. Their research-checkout paths and hashes are identified in the source manifest. [R7]

The task pipeline executes in this order:

```text
Apply the generated patch
Extract dependency changes
Install dependencies and run functional tests
Run the guard and record policy decisions
```

In `pipeline/run_task.py`, `setup_venv` and the public and hidden functional tests precede `run_guard`. **The current task pipeline is not a pre-installation attack-prevention system.** A Python virtual environment separates dependency environments; it is not a complete operating-system security boundary. Pre-installation checking, execution isolation, restricted credentials, and least privilege are proposed deployment improvements, not measured protection outcomes. [R7]

## 4. Data and units of analysis

| Retained material | Size | Use |
|---|---:|---|
| Full Python observation corpus | 8,752 changes; 1,101 pull requests | Descriptive public-record criterion matches |
| Non-exact declaration frame | 5,790 declarations; 892 pull requests | Paired reporting-procedure comparison |
| Retained policy subset | 4,948 changes; 479 pull requests | Reference labels and policy actions |
| Controlled benchmark records | 1,200 records; 120 tasks; five models | Supporting fixed-patch policy stress test |
| Follow-up external manifest sample | 12 declarations and packages; two projects | Limited same-information baseline comparison |

A pull request (PR) can contain several dependency changes. A declaration specifies an allowed version or version range. A release token is a version identifier in retained package metadata. Counts at these levels must not be substituted for one another.

The benchmark contains 600 records in each generation condition, G0 and G1. Its generator population differs from that of the observed PR corpus. A fixed-patch policy comparison may preserve functional success by construction. Shared evidence between checks and reference labels limits independence; the benchmark is not independent validation of naturalistic results. [R1, R8]

The final naturalistic reference labels incorporate exact-pin re-verification prompted by an audit of disagreements with the guard. Although the correction rule uses public records, the final procedure is not described as guard-independent. The present report preparation does not newly validate collection completeness, agent attribution, or the correctness of those labels. [R1]

## 5. Criterion matches and policy actions

### 5.1 Full corpus

Of the 8,752 observed changes, 279 match the defined public-record criteria: **279 / 8,752 = 3.19%**. This is a descriptive result for a convenience corpus. It is not a count of independently established exploitable vulnerabilities, nor an estimate of risk across all AI-generated dependencies. Support for exact versions and non-exact declarations differs, so assessment coverage must accompany any denominator. [R1]

### 5.2 Retained policy subset

The retained subset contains **278 reference-positive changes**, not the full corpus's 279. For E0/v2, the B3 full policy produces the following actions. [R2]

| Action | Reference-positive changes | Reference-negative changes |
|---|---:|---:|
| BLOCK | 169 | 141 |
| WARN | 105 | 80 |
| PASS | 4 | 4,449 |
| Total | 278 | 4,670 |

Positive intervention coverage is **274 / 278 = 98.6%** when warnings and blocks are combined. Positive blocking coverage is **169 / 278 = 60.8%**. A warning is not a block, and neither proportion is presented as general security recall. The reference criteria and checks share evidence semantics, and a reference-negative change is not independently known to be safe.

Of 141 blocks of reference-negative changes, 136 fire S5 alone. This establishes the influence of license policy relative to the primary reference construct. It does not establish 136 security false positives.

Units also affect interpretation. Among 364 PRs whose changes are all primary-reference-negative, 57 contain a block and 72 contain a warning or block. Across the same PRs' 3,040 changes, 97 are blocked and 140 receive an intervention. A change-level percentage cannot directly represent PR-level review workload. [R2]

## 6. Reporting sensitivity and remaining uncertainty

The two reporting procedures, C0 and Calt, use the same 5,790 non-exact declarations and archived records. However, Calt changes supported scope and completeness handling while conditionally inheriting originally determinate states. Retention of positive raw evidence is also part of its construction. The comparison measures sensitivity to reporting rules; it is not an accuracy comparison between two detectors answering the same question. [R1]

| Outcome or transition cause | Declarations |
|---|---:|
| C0 UNKNOWN | 1,844 |
| Calt UNKNOWN | 503 |
| State transitions | 1,341 |
| Coordinate or support-scope changes | 1,241 |
| Supported-positive saturation | 97 |
| Empty observed release sets | 3 |

Transitions are concentrated. The ten packages with the most transitions account for **976 / 1,341 = 72.78%**. The declaration-weighted transition rate is 23.16%; averaging within-package rates with equal package weights gives 5.47%. These answer different descriptive questions. Reweighting does not identify a true population rate, correct all selection bias, or establish a causal effect of a package. The top packages were selected after observing the transitions. [R3]

The 503 residual UNKNOWN outcomes have the following reported decomposition. [R1]

| Residual issue | Declarations |
|---|---:|
| Indeterminate version membership | 293 |
| Determinate membership with incomplete release data | 179 |
| Unsupported constraints | 18 |
| Unavailable metadata | 13 |

Within the 179, upload-date gaps affect 148 declarations linked to 163 distinct package/release-token entries. All 163 retained entries have `files=[]`. Reading an existing timestamp field cannot fill a date when no file object exists. This is an observed metadata form, not a newly discovered PyPI vulnerability. Individual deletion histories and recoverability from external archives were not established. [R3]

## 7. Follow-up analyses and counterevidence

### 7.1 Finite release-date completions

A post-hoc analysis selected 79 declarations from 33 packages with unresolved upload dates but no advisory-channel errors. Holding the retained release keys and matcher fixed, it considered inclusion or exclusion of date-unknown tokens. The resulting category was invariant for all selected declarations: 58 were NO_OBSERVED_MATCH and 21 were SOME_OBSERVED_MATCH. Their release inventories remained incomplete. Of the 58 NO cases, 57 had no relevant pre-cutoff advisory. [R3]

This completion model excludes missing release keys, new or corrected advisories, and removal or correction of known witnesses. The 79 declarations remain UNKNOWN in the original Calt outputs. They are not subtracted from 503, and this is not a reduction to 424. The analysis applies elementary set reasoning to a limited retained sample; it does not establish a new general inference principle or sufficient journal novelty.

### 7.2 A positive witness within an unresolved category

An unresolved full category and a supported positive existence answer are different outputs. The narrower question asks whether at least one known, allowed stable release token matches a supported advisory in the retained records. A historical verification checked one selected witness in each of 1,202 eligible C0-UNKNOWN declarations, including 339 residual Calt-UNKNOWN declarations. It checked declaration interpretation, version allowance, recorded upload date, advisory publication conditions, and agreement with the retained matcher. No witness mismatches were recorded. [R4]

Of the residual 339, 318 still had other advisory-channel errors. The remaining 21 are exactly the SOME cases in the finite-completion analysis. Adding 79 and 339 as independent resolved cases would double count overlapping analyses and misstate their questions.

Publication dates do not reconstruct historical database contents. The selected advisory record was modified after the PR cutoff in 956 of the 1,202 rows, including 230 of the residual 339. These are row counts, not distinct advisory counts. A later modification does not prove that the earlier match was wrong; it also does not establish that the current affected range existed at PR time. The proportion 339 / 503 is neither accuracy improvement nor measured review-time savings. [R4]

### 7.3 Comparison with existing details and a same-information baseline

The follow-up comparison did not treat a single UNKNOWN status as the strongest available baseline. It examined both a simple aggregation using the same supported information and existing detailed scanner outputs. [R5]

| Comparison | Recorded result |
|---|---:|
| Candidate versus same-information aggregation on existing declarations | 5,790 rows; zero output differences |
| Selected C0-UNKNOWN witnesses present in existing native details | 1,202 / 1,202 |
| Residual Calt-UNKNOWN witnesses present in those details | 339 / 339 |
| Selected advisory content matched the existing native input revision by hash | 1,202 / 1,202 |
| Candidate versus same-information aggregation on new manifest declarations | 12 rows; zero output differences |

The historical native results used OSV-Scanner 2.6.0, commit `e840a6e8adb14b7777c78e26cfbf6e2abc1d1fc6`. The comparison reused saved results; it did not rerun the scanner. The 339 residual witnesses were not new detections missed by that scanner. The simple baseline and candidate test the same positive-existence condition on the same supported set, so the comparison does not establish a distinct positive-inference advantage.

The external manifest sample selected 12 declarations and 12 packages from pypa/pip-audit and python-poetry/poetry. A prespecified third project, pypa/warehouse, was excluded because it lacked the required static production-dependency field. Two selected declarations had supported positive witnesses, and the baseline returned the same answers. This convenience sample's 2 / 12 is not a general risk rate. The study did not evaluate selected lockfile versions, installation, reachability, exploitability, or new native scans on these cases. [R5]

These negative comparisons constrain claims of detection novelty. Presenting question-specific evidence might still help a reviewer, but actual task decisions, errors, investigation choices, and time were not measured. Formatting the same information differently is not, by itself, evidence of practical benefit.

## 8. Reproducibility and the present reverse-check

### 8.1 Historical policy replay

A historical Slurm batch execution, job 16411, extracted a frozen replay attachment outside the original checkout and recalculated five scenarios: E0/v1, E0/v2, E0/v3, E1/v2, and E1/v3. Each scenario's 8,752 rows matched its saved expected ledger. Retained-v1 and retained-v2 decisions and fired stages also matched for 4,948 changes each. The artifact retained 27 original code modules without byte changes and verified 5,638 manifest-listed files. These are statements from the historical execution record, not a new policy run performed while preparing this report. [R2]

The total of 5 × 8,752 = 43,760 scenario-output rows does not represent independent observations or newly discovered vulnerabilities. Output equality supports implementation reproducibility under fixed inputs. It does not validate the reference truth, public-data accuracy, installed safety, or practical impact.

The separate replay attachment is identified by:

```text
Filename: asg-retained-v2-20261105-v1.tar.gz
Size:     96,038,178 bytes
SHA-256:  5fea32b4a134f5d1ccf8372da33ced27efe652a659c2a07c4f2101a28e0731f5
```

The attachment is not included in the lightweight report snapshot. Public redistribution and a download location have not been established here. A hash identifies bytes; it does not provide access or permission to redistribute them.

If the attachment is obtained through an authorized distribution route, its retained requirements are Python 3.10 or later, `packaging==26.0`, and a real Slurm batch job for policy execution. The recorded recommended request is one node, one CPU, 4 GB memory, and 20 minutes; no GPU or Docker is needed. Inside the extracted attachment, the following commands have different scopes:

```bash
# File integrity only; no policy execution and no Slurm requirement.
python3 -I replay.py --verify-only

# Run inside a real Slurm batch job; output must be new and outside the artifact.
python3 -I replay.py --out /absolute/path/to/new-results
```

These commands refer to the separate attachment, not to a `replay.py` included with this report. Do not disable assertions with `-O`, fabricate Slurm environment values, or remove execution restrictions. Follow the host cluster's authorized batch-submission procedure.

### 8.2 Reverse-check of this report

The English-edition preparation checked previously cited source hashes and freshly aggregated stored rows rather than only checking summary arithmetic. It reconstructed the full criterion-label counts from the retained label table and correction ledger; recounted the retained guard actions and PR-level outcomes; paired the stored C0/Calt ledgers by change identifier; checked finite-category rows; and compared the row-level same-information, existing-native-witness, and external-manifest records. It also checked that installation and tests precede the guard in the source code. These checks did not invoke the original evaluators, fetch metadata, install packages, or run models or scanners.

This reverse-check addresses numerical consistency, traceability, omitted counterevidence, and claim scope. It does not independently authenticate the original observations. Shared data and saved outputs remain shared, even when aggregation code is written again.

The lightweight snapshot's separate command, `python3 scripts/verify.py`, checks file integrity, local links, report markers, and aggregate consistency. It does not reproduce the row-level research or the historical policy execution. The source manifest identifies local research inputs and hashes; most raw inputs are not distributed in this snapshot.

## 9. Uses, limitations, and follow-up requirements

The useful record is the connection between declared questions, observation units, evidence support, reporting uncertainty, and policy actions. A follow-up implementation can record package and version coordinates, cutoff dates, advisory revision, completeness status, and the reason for each action. Separating license decisions from vulnerability signals and retaining uncertainty can make a result easier to interpret. Operational benefit from these practices remains a hypothesis here.

The principal limitations are:

- **Sampling and repetition.** This is a convenience corpus with repeated upstream packages and records. Results do not automatically generalize to other ecosystems, periods, or all AI coding agents.
- **Researcher-selected reporting procedures.** C0 and Calt are exploratory contracts, not demonstrated representative defaults of deployed tools.
- **Shared evidence.** Labels, checks, and follow-up implementations share retained metadata and some libraries. Agreement is not independent security truth.
- **Temporal uncertainty.** Filtering by advisory publication date does not recover the complete historical advisory revision or deleted release history.
- **Execution scope.** Neither functional tests nor fixed-output policy replay establish exploitability or attack-prevention rates. The task pipeline evaluates the guard after installation and tests.
- **Limited external comparison.** Twelve declarations address a positive-existence question, not an external replication of every assessment state or a native-scanner superiority experiment.
- **Unmeasured human benefit.** No reviewer study establishes better decisions, less investigation, or time savings.
- **Partial distribution.** This report snapshot omits raw inputs and the full replay attachment. Hashes do not establish public access or redistribution rights.
- **Unestablished novelty sufficiency.** Reframing the work as a technical report and repeating agent reviews do not add empirical evidence or establish journal acceptance.

Stronger claims require matching evidence. Detection accuracy requires an appropriate independent reference standard. Reviewer benefit requires actual tasks and a comparison condition with access to the same detailed information. Installed safety requires evidence about resolution, environment, and relevant execution behavior under suitable isolation. Those experiments are not reported as completed.

## 10. Conclusion

The retained AgentSupplyGuard work documents public-evidence assessment and policy actions for Python dependency changes. Reporting rules materially affect UNKNOWN counts, and criterion matches do not uniformly become blocks. Follow-up witness analyses clarify which narrower questions can be answered, but their positive outputs were also available from existing details and a same-information baseline. The appropriate technical record therefore includes both the descriptive findings and the unsuccessful stronger contribution claims. It does not claim improved independent security accuracy, a new detection principle, deployed protection, or sufficient journal novelty.

## References, provenance, and assistance

The accompanying [source manifest](../data/source_manifest.json) maps R1–R8 to research-checkout paths, SHA-256 hashes, and inclusion status. Most original artifacts are not included in this snapshot; the manifest is a provenance record, not a promise of public availability.

- **R1:** Frozen manuscript, 4 November 2026, *Assessability of Python Dependency Changes in AI-Agent-Attributed Pull Requests: Reporting Sensitivity and Policy Replay*. Source for corpus counts, reporting-contract results, and the residual decomposition; not a claim of journal publication.
- **R2:** Retained-v2 reproduction report, historical verification receipt, and retained tables, 5 November 2026. Source for the historical replay and policy-action results.
- **R3:** Contribution-mechanisms report, aggregate results, finite-category results, and verification, 5 November 2026. Post-hoc analyses, not a new population or independent security standard.
- **R4:** Question-specific-evidence report and selected-witness verification, 5 November 2026. Scope-limited support and timing checks.
- **R5:** Sufficiency-baseline-transfer report and baseline/transfer results, 5 November 2026. Counterevidence to a distinct positive-inference advantage.
- **R6:** Sufficiency-debate-v2 synthesis, 5 November 2026. Internal discussion of contribution sufficiency; not independent peer-review evidence.
- **R7:** Original extraction, stage, guard, installation, and test code. Source for implementation scope and execution order.
- **R8:** `results/offline_v2/canonical_runs.jsonl`. Source for the supporting benchmark frame.

Conceptual documentation includes the [PyPI JSON API](https://docs.pypi.org/api/json/), [OSV schema](https://ossf.github.io/osv-schema/), and [OSV-Scanner output documentation](https://google.github.io/osv-scanner/output/). These web references were not newly retrieved during report preparation and do not validate current behavior or reconstruct historical database contents. No systematic literature search or firstness claim is made.

Codex assisted with source inspection, aggregation checks, drafting and translation, and snapshot preparation. This assistance is not external independent review or human validation. The original license and attribution are retained; final authorship, contributor wording, and the public distribution scope require confirmation before any public release.
