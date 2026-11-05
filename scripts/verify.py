"""Check this report snapshot, not the original policy or security accuracy."""
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def verify():
    manifest = load("SHA256SUMS.json")
    files = set()
    for p in ROOT.rglob("*"):
        relative = p.relative_to(ROOT)
        if ".git" in relative.parts:
            continue
        require(not p.is_symlink(), f"Symlink outside snapshot policy: {relative}")
        if "__pycache__" in relative.parts:
            continue
        if p.is_file():
            files.add(relative.as_posix())
    require(files == set(manifest) | {"SHA256SUMS.json"}, "Missing or unexpected snapshot files")
    for name, expected in manifest.items():
        path = ROOT / name
        require(path.resolve().is_relative_to(ROOT), f"Path outside snapshot: {name}")
        require(path.stat().st_size == expected["bytes"], f"Size mismatch: {name}")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected["sha256"], f"Hash mismatch: {name}")

    links = 0
    for name in files:
        if not name.endswith(".md"):
            continue
        path = ROOT / name
        for target in re.findall(r"\[[^\]]*\]\(([^)\s]+)\)", path.read_text(encoding="utf-8")):
            uri = urlsplit(target.strip("<>"))
            if uri.scheme or not uri.path:
                continue
            resolved = (path.parent / unquote(uri.path)).resolve()
            require(resolved.is_relative_to(ROOT) and resolved.is_file(), f"Broken local link: {name}: {target}")
            links += 1

    data = load("data/aggregates.json")
    full, retained = data["full_cohort"], data["retained"]
    require(full["changes"] == 8752 and full["prs"] == 1101 and full["reference_positive"] == 279, "Full cohort changed")
    require(retained["changes"] == 4948 and retained["prs"] == 479, "Retained frame changed")
    positive, negative = retained["positive_actions"], retained["negative_actions"]
    require(positive == {"BLOCK": 169, "WARN": 105, "PASS": 4}, "Positive policy actions changed")
    require(negative == {"BLOCK": 141, "WARN": 80, "PASS": 4449}, "Negative policy actions changed")
    require(sum(positive.values()) == retained["reference_positive"] == 278, "Positive denominator mismatch")
    require(sum(negative.values()) + sum(positive.values()) == retained["changes"], "Retained denominator mismatch")
    contract = data["reporting_contracts"]
    require(contract["unknown_c0"] - contract["unknown_calt"] == sum(contract["transition_causes"].values()) == 1341, "Transition arithmetic mismatch")
    require(sum(contract["residual_causes"].values()) == contract["unknown_calt"] == 503, "Residual arithmetic mismatch")
    category = load("data/category_analysis.json")
    require(sum(category["determinate_states"].values()) == category["determinate_rows"] == 79, "Category arithmetic mismatch")
    witness = load("data/witness_verification.json")
    require(witness["original_unknown_witnesses_verified"] == 1202 and witness["residual_unknown_witnesses_verified"] == 339, "Witness count mismatch")
    baseline = load("data/baseline_comparison.json")
    require(baseline["same_information_output_mismatches"] == 0 and baseline["residual_selected_witness_present_in_existing_native"] == 339, "Baseline evidence mismatch")
    transfer = load("data/transfer_comparison.json")
    require(transfer["evaluated"] == 12 and transfer["positive"] == 2 and transfer["candidate_generic_mismatches"] == 0, "Transfer evidence mismatch")
    receipt = load("data/historical_replay_receipt.json")
    require(len(receipt["exact_full_ledger_matches"]) == 5 and set(receipt["exact_full_ledger_matches"].values()) == {8752}, "Historical replay receipt mismatch")
    require(all(v["retained_changes"] == 4948 and v["mismatches"] == 0 for v in receipt["retained_regressions"].values()), "Retained historical receipt mismatch")
    report = (ROOT / "docs/TECHNICAL_REPORT.en.md").read_text(encoding="utf-8")
    require(not re.search(r"[\uac00-\ud7a3]", report), "Unexpected Korean text in English report")
    for marker in ["8,752", "1,101", "5,790", "1,844", "503", "1,341", "1,241", "274 / 278", "169 / 278", "339 / 339", "not a pre-installation attack-prevention system", "zero output differences", "not an accuracy comparison"]:
        require(marker in report, f"Report marker missing: {marker}")
    return dict(snapshot_files=len(files), local_links_checked=links,
                file_hashes_and_inventory_pass=True, aggregate_arithmetic_pass=True,
                policy_replay_executed=False, independent_security_accuracy_verified=False,
                scope="Report snapshot integrity and aggregate checks only")


if __name__ == "__main__":
    try:
        print(json.dumps(verify(), ensure_ascii=False, indent=2))
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"Verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
