#!/usr/bin/env python3
"""Predeclared paired scoring for the blind saved-memory study."""

import argparse
import json
import os
from pathlib import Path
import random
import statistics


def percentile(values, fraction):
    ordered = sorted(values)
    index = fraction * (len(ordered) - 1)
    low = int(index)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def paired_interval(pairs, seed, repetitions=20000):
    if not pairs:
        return [None, None]
    rng = random.Random(int(seed, 16) ^ 0xC10D)
    differences = []
    for _ in range(repetitions):
        sample = [pairs[rng.randrange(len(pairs))] for _ in pairs]
        differences.append(sum(first - second for first, second in sample) / len(sample))
    return [percentile(differences, 0.025), percentile(differences, 0.975)]


def summarize(manifest, state):
    rows = state["cases"]
    positives = [row for row in rows if row["kind"] == "positive"]
    controls = [row for row in rows if row["kind"] != "positive"]
    attempted = [row for row in rows if row["status"] != "planned"]
    attempted_positives = [row for row in positives if row["status"] != "planned"]
    attempted_controls = [row for row in controls if row["status"] != "planned"]
    methods = {}
    for method in ("structured", "entropy"):
        scored = [row for row in rows if "score" in row]
        pos_success = sum(bool(row.get("score", {}).get(method, {}).get("case_success")) for row in positives)
        control_success = sum(bool(row.get("score", {}).get(method, {}).get("case_success")) for row in controls)
        false_assignments = sum(row["score"][method]["false_assignments"] for row in scored)
        abstentions = sum(row["score"][method]["abstentions"] for row in scored)
        target_correct = sum(row["score"][method]["correct_targets"] for row in scored)
        target_count = sum(row["score"][method]["target_count"] for row in scored)
        candidate_recall = sum(sum(detail["reference_in_candidate_set"] for detail in
                                   row["score"][method]["details"].values()) for row in scored)
        costs = [row["score"][method] for row in scored]
        strata = {}
        for name, group in (("positive_two", [row for row in positives if row["connections"] == 2]),
                            ("positive_three", [row for row in positives if row["connections"] == 3]),
                            *((kind, [row for row in controls if row["kind"] == kind])
                              for kind in ("mismatch", "unrelated", "withheld"))):
            strata[name] = {"attempted": sum(row["status"] != "planned" for row in group),
                            "scored": sum("score" in row for row in group),
                            "case_success": sum(bool(row.get("score", {}).get(method, {}).get("case_success"))
                                                for row in group),
                            "false_assignments": sum(row.get("score", {}).get(method, {}).get("false_assignments", 0)
                                                     for row in group)}
        methods[method] = {"positive_complete": pos_success, "positive_attempted": len(attempted_positives),
                           "control_correct": control_success, "control_attempted": len(attempted_controls),
                           "false_assignments": false_assignments, "abstentions": abstentions,
                           "correct_targets": target_correct, "reference_targets_evaluated": target_count,
                           "reference_in_candidate_set": candidate_recall, "strata": strata,
                           "median_wall_seconds": statistics.median(item["wall_seconds"] for item in costs) if costs else None,
                           "median_cpu_seconds": statistics.median(item["cpu_seconds"] for item in costs) if costs else None,
                           "peak_rss_kib_max": max((item["peak_rss_kib"] for item in costs), default=None)}
    pairs = [(int(bool(row.get("score", {}).get("structured", {}).get("case_success"))),
              int(bool(row.get("score", {}).get("entropy", {}).get("case_success")))) for row in attempted_positives]
    difference = sum(first - second for first, second in pairs) / len(pairs) if pairs else None
    interval = paired_interval(pairs, manifest["seed"])
    scored_controls = sum("score" in row for row in controls)
    strong = (manifest["mode"] == "final" and len(attempted) == 100 and
              sum("score" in row for row in positives) == 70 and scored_controls == 30 and
              methods["structured"]["positive_complete"] >= 63 and
              methods["structured"]["false_assignments"] == 0 and
              methods["structured"]["false_assignments"] <= methods["entropy"]["false_assignments"] and
              interval[0] is not None and interval[0] > 0)
    return {"mode": manifest["mode"], "planned": len(rows), "attempted": len(attempted),
            "scored": sum("score" in row for row in rows), "status_counts":
            {status: sum(row["status"] == status for row in rows) for status in sorted({row["status"] for row in rows})},
            "methods": methods, "paired_complete_case_difference": difference,
            "paired_bootstrap_95_percent_interval": interval, "paired_bootstrap_repetitions": 20000,
            "strong_contribution_predeclared": strong}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--study", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.study / "manifest.json").read_text())
    state = json.loads((args.study / "state.json").read_text())
    result = summarize(manifest, state)
    (args.study / "summary.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    (args.study / "summary.json").chmod(0o600)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
