"""
analyse_dataset.py

Reads the normalised master experiment dataset and produces
research statistics in JSON and text formats.
"""

import csv
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent

DATASET_PATH = (
    PROJECT_ROOT
    / "results"
    / "datasets"
    / "master_experiment_dataset.csv"
)

OUTPUT_DIRECTORY = PROJECT_ROOT / "results" / "analysis"
JSON_OUTPUT = OUTPUT_DIRECTORY / "experiment_statistics.json"
TEXT_OUTPUT = OUTPUT_DIRECTORY / "experiment_statistics.txt"

OUTLIER_THRESHOLD_SECONDS = 60.0


def load_dataset() -> list[dict[str, str]]:
    """Load the normalised master CSV dataset."""

    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    with DATASET_PATH.open("r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def safe_float(value: str) -> float | None:
    """Convert a value to float safely."""

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def calculate_percentage(value: int, total: int) -> float:
    """Calculate a percentage safely."""

    if total == 0:
        return 0.0

    return round((value / total) * 100, 2)


def is_true(value: str) -> bool:
    """Return True when a CSV value represents true."""

    return str(value).strip().lower() == "true"


def main() -> None:
    rows = load_dataset()

    if not rows:
        print("The dataset contains no experiment records.")
        return

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    total_runs = len(rows)

    scenario_counts = Counter(row["scenario"] for row in rows)
    test_mode_counts = Counter(row["test_mode"] for row in rows)
    outcome_counts = Counter(row["security_outcome"] for row in rows)
    validation_counts = Counter(row["validation_passed"] for row in rows)
    mitre_counts = Counter(row["mitre_technique_id"] for row in rows)

    allowed_runs = sum(
        1
        for row in rows
        if row["security_outcome"].strip().lower() == "allowed"
    )

    blocked_runs = sum(
        1
        for row in rows
        if row["security_outcome"].strip().lower() == "blocked"
    )

    validation_passed = sum(
        1
        for row in rows
        if is_true(row["validation_passed"])
    )

    failed_validation_rows = []

    for row in rows:
        if not is_true(row["validation_passed"]):
            failed_validation_rows.append(
                {
                    "source_file": row["source_file"],
                    "run_id": row["run_id"],
                    "scenario": row["scenario"],
                    "test_mode": row["test_mode"],
                    "security_outcome": row["security_outcome"],
                    "validation_details": row["validation_details"],
                }
            )

    fallback_known_rows = [
        row
        for row in rows
        if row["fallback_used"].strip()
    ]

    fallback_used = sum(
        1
        for row in fallback_known_rows
        if is_true(row["fallback_used"])
    )

    missing_fallback_values = total_runs - len(fallback_known_rows)

    fallback_rate_known = calculate_percentage(
        fallback_used,
        len(fallback_known_rows),
    )

    durations: list[float] = []
    duration_by_scenario: dict[str, list[float]] = defaultdict(list)

    for row in rows:
        duration = safe_float(row["execution_time_seconds"])

        if duration is None:
            continue

        durations.append(duration)
        duration_by_scenario[row["scenario"]].append(duration)

    normal_durations = [
        duration
        for duration in durations
        if duration <= OUTLIER_THRESHOLD_SECONDS
    ]

    outlier_rows = []

    for row in rows:
        duration = safe_float(row["execution_time_seconds"])

        if duration is not None and duration > OUTLIER_THRESHOLD_SECONDS:
            outlier_rows.append(
                {
                    "source_file": row["source_file"],
                    "run_id": row["run_id"],
                    "scenario": row["scenario"],
                    "duration_seconds": duration,
                }
            )

    average_duration_by_scenario = {
        scenario: round(statistics.mean(values), 3)
        for scenario, values in duration_by_scenario.items()
        if values
    }

    median_duration_by_scenario = {
        scenario: round(statistics.median(values), 3)
        for scenario, values in duration_by_scenario.items()
        if values
    }

    summary = {
        "dataset": {
            "source": str(DATASET_PATH),
            "total_rows": total_runs,
            "total_columns": len(rows[0]),
        },
        "security_outcomes": {
            "allowed_runs": allowed_runs,
            "blocked_runs": blocked_runs,
            "allowed_percentage": calculate_percentage(allowed_runs, total_runs),
            "blocked_percentage": calculate_percentage(blocked_runs, total_runs),
            "outcome_distribution": dict(outcome_counts),
        },
        "validation": {
            "validation_passed": validation_passed,
            "validation_failed": len(failed_validation_rows),
            "validation_success_rate": calculate_percentage(
                validation_passed,
                total_runs,
            ),
            "validation_distribution": dict(validation_counts),
            "failed_validation_records": failed_validation_rows,
        },
        "fallback": {
            "records_with_fallback_data": len(fallback_known_rows),
            "fallback_used": fallback_used,
            "fallback_rate_among_recorded_runs": fallback_rate_known,
            "missing_fallback_values": missing_fallback_values,
        },
        "execution_time": {
            "recorded_durations": len(durations),
            "average_seconds": (
                round(statistics.mean(durations), 3)
                if durations
                else None
            ),
            "median_seconds": (
                round(statistics.median(durations), 3)
                if durations
                else None
            ),
            "minimum_seconds": round(min(durations), 3) if durations else None,
            "maximum_seconds": round(max(durations), 3) if durations else None,
            "outlier_threshold_seconds": OUTLIER_THRESHOLD_SECONDS,
            "outlier_count": len(outlier_rows),
            "outlier_records": outlier_rows,
            "average_excluding_outliers_seconds": (
                round(statistics.mean(normal_durations), 3)
                if normal_durations
                else None
            ),
            "median_excluding_outliers_seconds": (
                round(statistics.median(normal_durations), 3)
                if normal_durations
                else None
            ),
            "average_by_scenario": average_duration_by_scenario,
            "median_by_scenario": median_duration_by_scenario,
        },
        "scenario_distribution": dict(scenario_counts),
        "test_mode_distribution": dict(test_mode_counts),
        "mitre_technique_distribution": dict(mitre_counts),
    }

    with JSON_OUTPUT.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2, ensure_ascii=False)

    report_lines = [
        "=" * 72,
        "LLM AGENT SECURITY EVALUATION - DATASET ANALYSIS",
        "=" * 72,
        "",
        "DATASET SUMMARY",
        "-" * 72,
        f"Total experiment runs       : {total_runs}",
        f"Total dataset columns       : {len(rows[0])}",
        "",
        "SECURITY OUTCOMES",
        "-" * 72,
        f"Allowed outcomes            : {allowed_runs}",
        f"Blocked outcomes            : {blocked_runs}",
        f"Allowed percentage          : {summary['security_outcomes']['allowed_percentage']}%",
        f"Blocked percentage          : {summary['security_outcomes']['blocked_percentage']}%",
        "",
        "OUTPUT VALIDATION",
        "-" * 72,
        f"Validation passed           : {validation_passed}",
        f"Validation failed           : {len(failed_validation_rows)}",
        f"Validation success rate     : {summary['validation']['validation_success_rate']}%",
        "",
        "SAFE FALLBACK",
        "-" * 72,
        f"Records with fallback data  : {len(fallback_known_rows)}",
        f"Fallback used               : {fallback_used}",
        f"Fallback rate recorded runs : {fallback_rate_known}%",
        f"Missing fallback values     : {missing_fallback_values}",
        "",
        "EXECUTION TIME",
        "-" * 72,
        f"Recorded durations          : {len(durations)}",
        f"Average duration            : {summary['execution_time']['average_seconds']} seconds",
        f"Median duration             : {summary['execution_time']['median_seconds']} seconds",
        f"Minimum duration            : {summary['execution_time']['minimum_seconds']} seconds",
        f"Maximum duration            : {summary['execution_time']['maximum_seconds']} seconds",
        f"Outlier threshold           : {OUTLIER_THRESHOLD_SECONDS} seconds",
        f"Timing outliers             : {len(outlier_rows)}",
        f"Average excluding outliers  : {summary['execution_time']['average_excluding_outliers_seconds']} seconds",
        f"Median excluding outliers   : {summary['execution_time']['median_excluding_outliers_seconds']} seconds",
        "",
        "RUNS BY SCENARIO",
        "-" * 72,
    ]

    for scenario, count in sorted(scenario_counts.items()):
        report_lines.append(f"{scenario}: {count}")

    report_lines.extend(["", "RUNS BY TEST MODE", "-" * 72])

    for mode, count in sorted(test_mode_counts.items()):
        report_lines.append(f"{mode}: {count}")

    report_lines.extend(
        ["", "MITRE / ATLAS TECHNIQUE DISTRIBUTION", "-" * 72]
    )

    for technique, count in sorted(mitre_counts.items()):
        report_lines.append(f"{technique}: {count}")

    report_lines.extend(
        ["", "AVERAGE EXECUTION TIME BY SCENARIO", "-" * 72]
    )

    for scenario, average in sorted(average_duration_by_scenario.items()):
        report_lines.append(f"{scenario}: {average} seconds")

    report_lines.extend(
        ["", "MEDIAN EXECUTION TIME BY SCENARIO", "-" * 72]
    )

    for scenario, median in sorted(median_duration_by_scenario.items()):
        report_lines.append(f"{scenario}: {median} seconds")

    report_lines.extend(["", "TIMING OUTLIER RECORDS", "-" * 72])

    if outlier_rows:
        for record in sorted(
            outlier_rows,
            key=lambda item: item["duration_seconds"],
            reverse=True,
        ):
            report_lines.append(
                f"{record['run_id']} | "
                f"{record['scenario']} | "
                f"{record['duration_seconds']} seconds"
            )
    else:
        report_lines.append("No timing outliers detected.")

    report_lines.extend(["", "FAILED VALIDATION RECORDS", "-" * 72])

    if failed_validation_rows:
        for record in failed_validation_rows:
            report_lines.append(
                f"{record['run_id']} | "
                f"{record['scenario']} | "
                f"{record['validation_details']}"
            )
    else:
        report_lines.append("No failed validations.")

    report = "\n".join(report_lines)

    with TEXT_OUTPUT.open("w", encoding="utf-8") as file:
        file.write(report)

    print(report)
    print()
    print(f"JSON report saved to : {JSON_OUTPUT}")
    print(f"Text report saved to : {TEXT_OUTPUT}")


if __name__ == "__main__":
    main()
