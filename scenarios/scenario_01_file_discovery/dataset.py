import csv
import json
from pathlib import Path


LOG_DIRECTORY = Path("/agent_project/logs/raw")

OUTPUT_DIRECTORY = Path("/agent_project/results/datasets")

OUTPUT_FILE = OUTPUT_DIRECTORY / "scenario_01_dataset.csv"


def main():

    print("\n===== SCENARIO 01 DATASET BUILDER =====")

    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_files = sorted(
        LOG_DIRECTORY.glob("S01-*.json")
    )

    if not log_files:
        print("No Scenario 01 logs were found.")
        return

    print("Logs found:", len(log_files))

    dataset_rows = []

    for log_file in log_files:

        print("Processing:", log_file.name)

        with log_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        requested_tools = data["agent"]["requested_tools"]

        security_events = data["security"]["events"]

        tool_results = data["execution"]["tool_results"]

        requested_tool_names = [
            tool["tool_name"]
            for tool in requested_tools
        ]

        allowed_tools = [
            event["tool_name"]
            for event in security_events
            if event["decision"] == "allowed"
        ]

        blocked_tools = [
            event["tool_name"]
            for event in security_events
            if event["decision"] == "blocked"
        ]

        dataset_row = {
            "run_id": data["run_id"],

            "scenario_id": data["scenario"]["id"],

            "scenario_name": data["scenario"]["name"],

            "model": data["environment"]["model"],

            "framework": data["environment"]["framework"],

            "started_at": data["timestamps"]["started_at"],

            "duration_seconds":
                data["timestamps"]["duration_seconds"],

            "requested_tools":
                "|".join(requested_tool_names),

            "allowed_tools":
                "|".join(allowed_tools),

            "blocked_tools":
                "|".join(blocked_tools),

            "tool_execution_count":
                len(tool_results),

            "validation_status":
                data["validation"]["status"],

            "final_response":
                data["agent"]["final_response"],

            "mitre_technique_id":
                data["mitre_attack"]["technique_id"],

            "mitre_technique_name":
                data["mitre_attack"]["technique_name"],

            "mapping_status":
                data["mitre_attack"]["mapping_status"],
        }

        dataset_rows.append(dataset_row)

    fieldnames = list(dataset_rows[0].keys())

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(dataset_rows)

    print("\n===== DATASET COMPLETE =====")

    print("Experiment records:", len(dataset_rows))

    print("Dataset saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
