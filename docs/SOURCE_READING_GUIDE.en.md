# Selected implementation files

These ten Python files are verbatim copies of the implementation cited in the technical record. They are provided for reading, not as a standalone execution or policy-replay package. Other imported modules, configurations, task inputs, and evidence snapshots are omitted. The files retain their original comments and terminology; those comments do not establish independently measured security accuracy.

| File | What to inspect |
| --- | --- |
| [dep_extractor.py](../pipeline/dep_extractor.py) | Dependency declaration parsing and change extraction. |
| [decision.py](../pipeline/guard/decision.py) | Enabled stages and aggregation into PASS, WARN, or BLOCK. |
| [s1_package_existence.py](../pipeline/guard/s1_package_existence.py) | Package-existence checks against saved evidence and missing-evidence handling. |
| [s2_version_validity.py](../pipeline/guard/s2_version_validity.py) | Declared versions and constraints compared with release evidence. |
| [s3_direct_vulnerability.py](../pipeline/guard/s3_direct_vulnerability.py) | Direct-dependency checks against saved advisory evidence. |
| [s4_transitive_vulnerability.py](../pipeline/guard/s4_transitive_vulnerability.py) | Transitive-dependency checks using saved dependency and advisory evidence. |
| [s5_license_policy.py](../pipeline/guard/s5_license_policy.py) | License-policy rules, separate from vulnerability findings. |
| [s6_dependency_restraint.py](../pipeline/guard/s6_dependency_restraint.py) | Conditions restricting external dependencies. |
| [run_task.py](../pipeline/run_task.py) | The historical task orchestration and its installation, test, and guard order. |
| [test_runner.py](../pipeline/test_runner.py) | Virtual-environment creation, dependency installation, and test invocation. |

In the supplied `run_task.py` path, `setup_venv` and `run_tests` precede `run_guard`, including in the repair path. A recorded BLOCK therefore does not demonstrate pre-installation protection. A Python virtual environment separates dependency environments; it is not an operating-system security sandbox.

The original task runner can install dependencies and invoke tests. Reading these files requires neither action. `python3 scripts/verify.py` checks the repository inventory, file hashes, and saved aggregate arithmetic. It does not import or execute the supplied task runner or guard stages, install their dependencies, replay policies, or test exploitability.

[code_manifest.json](../data/code_manifest.json) records the selected files' relative source paths, byte sizes, and SHA-256 hashes. [SHA256SUMS.json](../SHA256SUMS.json) covers the distributed snapshot. Hash agreement establishes byte identity, not security effectiveness. Original license and attribution notices remain in [LICENSE](../LICENSE) and [NOTICE.md](../NOTICE.md).

Raw PR records, registry responses, advisory texts, unpublished manuscript PDFs, full replay archives, and course reports or slides are not added by this source-reading supplement. See the [English technical report](TECHNICAL_REPORT.en.md) for the analysis and its limits.
