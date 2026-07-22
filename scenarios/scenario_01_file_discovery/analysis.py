import csv
from collections import Counter
from pathlib import Path
from statistics import mean


DATASET_FILE = Path(
    "/agent_project/results/datasets/scenario_01_dataset.csv"
)

OUTPUT_DIRECTORY = Path(
    "/agent_project/results/analysis"
)

OUTPUT_FILE = OUTPUT_DIRECTORY / "scenario_01_summary.txt"


def load_dataset() -> list[dict]:
    """Load all experiment rows from the Scenario 1 CSV dataset."""

    if not DATASET_FILE.exists():
        raise FileNotFoundError(
            f"Dataset was not found: {DATASET_FILE}"
        )

    with DATASET_FILE.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.DictReader(file)
        return list(reader)


def split_tool_names(value: str) -> list[str]:
    """Split pipe-separated tool names stored in the CSV."""

    if not value.strip():
        return []

    return [
        item.strip()
        for item in value.split("|")
        if item.strip()
    ]


def main() -> None:
    """Analyse Scenario 1 experiment results."""

    print("\n===== SCENARIO 01 DATA ANALYSIS =====")

    rows = load_dataset()

    if not rows:
        print("The dataset contains no experiment records.")
        return

    total_runs = len(rows)

    validation_counts = Counter(
        row["validation_status"]
        for row in rows
    )

    durations = [
        float(row["duration_seconds"])
        for row in rows
    ]

    requested_tool_counter = Counter()
    allowed_tool_counter = Counter()
    blocked_tool_counter = Counter()
    mitre_counter = Counter()

    total_tool_executions = 0

    for row in rows:
        requested_tool_counter.update(
            split_tool_names(row["requested_tools"])
        )

        allowed_tool_counter.update(
            split_tool_names(row["allowed_tools"])
        )

        blocked_tool_counter.update(
            split_tool_names(row["blocked_tools"])
        )

        total_tool_executions += int(
            row["tool_execution_count"]
        )

        mitre_key = (
            f"{row['mitre_technique_id']} - "
            f"{row['mitre_technique_name']}"
        )

        mitre_counter[mitre_key] += 1

    passed_runs = validation_counts.get("passed", 0)
    warning_runs = validation_counts.get("warning", 0)
    failed_runs = validation_counts.get("failed", 0)

    validation_pass_rate = (
        passed_runs / total_runs
    ) * 100

    average_duration = mean(durations)
    fastest_duration = min(durations)
    slowest_duration = max(durations)

    requested_tool_count = sum(
        requested_tool_counter.values()
    )

    allowed_tool_count = sum(
        allowed_tool_counter.values()
    )

    blocked_tool_count = sum(
        blocked_tool_counter.values()
    )

    tool_selection_rate = (
        requested_tool_count / total_runs
    ) * 100

    lines = [
        "===== SCENARIO 01 ANALYSIS SUMMARY =====",
        "",
        f"Total experiment runs: {total_runs}",
        f"Validation passed: {passed_runs}",
        f"Validation warnings: {warning_runs}",
        f"Validation failed: {failed_runs}",
        (
            "Validation pass rate: "
            f"{validation_pass_rate:.2f}%"
        ),
        "",
        (
            "Average experiment duration: "
            f"{average_duration:.2f} seconds"
        ),
        f"Fastest run: {fastest_duration:.2f} seconds",
        f"Slowest run: {slowest_duration:.2f} seconds",
        "",
        f"Tool requests: {requested_tool_count}",
        f"Allowed tool requests: {allowed_tool_count}",
        f"Blocked tool requests: {blocked_tool_count}",
        f"Tool executions: {total_tool_executions}",
        (
            "Tool selection rate: "
            f"{tool_selection_rate:.2f}%"
        ),
        "",
        "Requested tool frequency:",
    ]

    if requested_tool_counter:
        for tool_name, count in requested_tool_counter.items():
            lines.append(
                f"- {tool_name}: {count}"
            )
    else:
        lines.append("- No tools were requested.")

    lines.append("")
    lines.append("Allowed tool frequency:")

    if allowed_tool_counter:
        for tool_name, count in allowed_tool_counter.items():
            lines.append(
                f"- {tool_name}: {count}"
            )
    else:
        lines.append("- No tools were allowed.")

    lines.append("")
    lines.append("Blocked tool frequency:")

    if blocked_tool_counter:
        for tool_name, count in blocked_tool_counter.items():
            lines.append(
                f"- {tool_name}: {count}"
            )
    else:
        lines.append("- No tools were blocked.")

    lines.append("")
    lines.append("MITRE ATT&CK mapping frequency:")

    for technique, count in mitre_counter.items():
        lines.append(
            f"- {technique}: {count}"
        )

    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_FILE.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    for line in lines:
        print(line)

    print()
    print("Analysis saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
