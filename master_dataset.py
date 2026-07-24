"""
master_dataset.py

Normalises experiment logs from different scenario schemas and creates
one research-ready CSV dataset.
"""

import csv
import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent
RAW_LOG_DIRECTORY = PROJECT_ROOT / "logs" / "raw"
OUTPUT_DIRECTORY = PROJECT_ROOT / "results" / "datasets"
OUTPUT_FILE = OUTPUT_DIRECTORY / "master_experiment_dataset.csv"


def get_nested(data: dict[str, Any], *keys: str) -> Any:
    """Safely retrieve a value from a nested dictionary."""

    current: Any = data

    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]

    return current


def first_available(*values: Any) -> Any:
    """Return the first value that is not None or empty."""

    for value in values:
        if value not in (None, "", [], {}):
            return value

    return None


def first_list_item(value: Any) -> dict[str, Any]:
    """Return the first dictionary from a list."""

    if isinstance(value, list) and value:
        first_item = value[0]

        if isinstance(first_item, dict):
            return first_item

    return {}


def detect_scenario(run_id: str, filename: str) -> str:
    combined = f"{run_id} {filename}".upper()

    if "S01" in combined:
        return "Scenario 01 - File Discovery"
    if "S02" in combined:
        return "Scenario 02 - Command Execution"
    if "S03" in combined:
        return "Scenario 03 - System Information"
    if "S04" in combined:
        return "Scenario 04 - Secure API Interaction"
    if "S05" in combined:
        return "Scenario 05 - Prompt Injection"

    return "Unknown"


def infer_test_mode(run_id: str, data: dict[str, Any]) -> str:
    mode = first_available(
        data.get("test_mode"),
        get_nested(data, "scenario", "test_mode"),
    )

    if mode:
        return str(mode).lower()

    upper_run_id = run_id.upper()

    if "INJECTION" in upper_run_id:
        return "injection"

    if "INVALID" in upper_run_id:
        return "invalid"

    if "BLOCKED" in upper_run_id:
        return "blocked"

    if "ALLOWED" in upper_run_id:
        return "allowed"

    if "READ" in upper_run_id:
        return "allowed"

    if upper_run_id.startswith("S01-"):
        return "allowed"

    if upper_run_id.startswith("S02-CMD-"):
        return "allowed"

    return "unknown"

def normalise_boolean(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"

    if value is None:
        return ""

    text = str(value).strip().lower()

    if text in {"true", "yes", "passed", "pass", "success", "successful"}:
        return "true"

    if text in {"false", "no", "failed", "failure", "fail"}:
        return "false"

    return text


def normalise_text(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)

    return str(value).strip()


def extract_tool_record(data: dict[str, Any]) -> dict[str, Any]:
    possible_lists = [
        data.get("tool_calls"),
        get_nested(data, "agent", "requested_tools"),
        get_nested(data, "execution", "tool_results"),
    ]

    for possible_list in possible_lists:
        record = first_list_item(possible_list)

        if record:
            return record

    return {}


def extract_mitre(data: dict[str, Any]) -> tuple[str, str]:
    attack = data.get("mitre_attack")
    mapping = data.get("mitre_mapping")

    technique_id = first_available(
        get_nested(data, "mitre_attack", "technique_id"),
        get_nested(data, "mitre_mapping", "technique_id"),
    )

    technique_name = first_available(
        get_nested(data, "mitre_attack", "technique_name"),
        get_nested(data, "mitre_mapping", "technique_name"),
    )

    technique_text = first_available(
        get_nested(data, "mitre_mapping", "technique"),
        get_nested(data, "mitre_attack", "technique"),
    )

    if technique_text and not technique_id:
        text = str(technique_text)

        if " - " in text:
            technique_id, technique_name = text.split(" - ", 1)
        else:
            technique_id = text

    if isinstance(attack, str) and not technique_id:
        technique_id = attack

    if isinstance(mapping, str) and not technique_id:
        technique_id = mapping

    return (
        normalise_text(technique_id),
        normalise_text(technique_name),
    )


def infer_security_outcome(
    data: dict[str, Any],
    verified_output: str,
    tool_result: str,
) -> str:
    explicit_outcome = first_available(
        data.get("security_outcome"),
        data.get("policy_outcome"),
        data.get("final_status"),
    )

    if explicit_outcome:
        explicit_text = str(explicit_outcome).lower()

        if explicit_text in {"allowed", "approved", "success"}:
            return "allowed"

        if explicit_text in {"blocked", "denied", "rejected"}:
            return "blocked"

        if explicit_text == "completed":
            combined = f"{verified_output} {tool_result}".upper()

            if "BLOCKED:" in combined:
                return "blocked"

            return "allowed"

        return explicit_text

    combined = f"{verified_output} {tool_result}".upper()

    if "BLOCKED:" in combined:
        return "blocked"

    return "allowed"


def load_log(log_path: Path) -> dict[str, Any] | None:
    try:
        with log_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            print(f"Skipped non-object JSON: {log_path.name}")
            return None

        return data

    except json.JSONDecodeError as error:
        print(f"Skipped invalid JSON: {log_path.name}: {error}")

    except OSError as error:
        print(f"Could not read {log_path.name}: {error}")

    return None


def build_row(log_path: Path, data: dict[str, Any]) -> dict[str, str]:
    run_id = normalise_text(
        first_available(
            data.get("run_id"),
            data.get("experiment_id"),
            log_path.stem,
        )
    )

    scenario_id = normalise_text(
        first_available(
            data.get("scenario_id"),
            get_nested(data, "scenario", "id"),
        )
    )

    scenario_name = normalise_text(
        first_available(
            data.get("scenario_name"),
            get_nested(data, "scenario", "name"),
        )
    )

    tool_record = extract_tool_record(data)

    tool_name = normalise_text(
        first_available(
            tool_record.get("tool_name"),
            data.get("tool_name"),
            data.get("requested_tool"),
        )
    )

    tool_arguments = normalise_text(
        first_available(
            tool_record.get("arguments"),
            data.get("tool_arguments"),
        )
    )

    tool_result = normalise_text(
        first_available(
            tool_record.get("result"),
	    first_list_item(
                get_nested(data, "execution", "tool_results")
            ).get("result"),
        )
    )

    user_task = normalise_text(
        first_available(
            data.get("user_prompt"),
            get_nested(data, "input", "user_prompt"),
            data.get("task"),
        )
    )

    raw_response = normalise_text(
        first_available(
            data.get("raw_model_response"),
            get_nested(data, "agent", "raw_final_response"),
            data.get("raw_final_response"),
        )
    )

    effective_response = normalise_text(
        first_available(
            get_nested(data, "agent", "effective_final_response"),
            data.get("effective_final_response"),
            data.get("final_response"),
            raw_response,
        )
    )

    verified_output = normalise_text(
        first_available(
            data.get("verified_output"),
            get_nested(data, "validation", "expected_content"),
            tool_result,
        )
    )

    validation_status = first_available(
        data.get("validation_passed"),
        get_nested(data, "validation", "status"),
    )

    validation_details = normalise_text(
        first_available(
            data.get("validation_details"),
            get_nested(data, "validation", "details"),
        )
    )

    fallback_used = normalise_boolean(
        first_available(
            data.get("fallback_used"),
            get_nested(data, "agent", "fallback_used"),
        )
    )

    execution_time = first_available(
        data.get("duration_seconds"),
        get_nested(data, "timestamps", "duration_seconds"),
    )

    started_at = normalise_text(
        first_available(
            data.get("timestamp_started"),
            get_nested(data, "timestamps", "started_at"),
        )
    )

    completed_at = normalise_text(
        first_available(
            data.get("timestamp_completed"),
            get_nested(data, "timestamps", "completed_at"),
        )
    )

    mitre_id, mitre_name = extract_mitre(data)

    security_outcome = infer_security_outcome(
        data,
        verified_output,
        tool_result,
    )

    return {
        "source_file": log_path.name,
        "run_id": run_id,
        "scenario_id": scenario_id,
        "scenario": detect_scenario(run_id, log_path.name),
        "scenario_name": scenario_name,
        "test_mode": infer_test_mode(run_id, data),
        "tool_name": tool_name,
        "tool_arguments": tool_arguments,
        "tool_result": tool_result,
        "validation_passed": normalise_boolean(validation_status),
        "validation_details": validation_details,
        "fallback_used": fallback_used,
        "security_outcome": security_outcome,
        "mitre_technique_id": mitre_id,
        "mitre_technique_name": mitre_name,
        "execution_time_seconds": normalise_text(execution_time),
        "started_at": started_at,
        "completed_at": completed_at,
        "user_task": user_task,
        "raw_model_response": raw_response,
        "final_response": effective_response,
        "verified_output": verified_output,
    }


def main() -> None:
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    log_files = sorted(RAW_LOG_DIRECTORY.glob("*.json"))

    if not log_files:
        print(f"No JSON logs found in: {RAW_LOG_DIRECTORY}")
        return

    rows: list[dict[str, str]] = []

    for log_path in log_files:
        data = load_log(log_path)

        if data is not None:
            rows.append(build_row(log_path, data))

    if not rows:
        print("No valid JSON logs were available.")
        return

    fieldnames = [
        "source_file",
        "run_id",
        "scenario_id",
        "scenario",
        "scenario_name",
        "test_mode",
        "tool_name",
        "tool_arguments",
        "tool_result",
        "validation_passed",
        "validation_details",
        "fallback_used",
        "security_outcome",
        "mitre_technique_id",
        "mitre_technique_name",
        "execution_time_seconds",
        "started_at",
        "completed_at",
        "user_task",
        "raw_model_response",
        "final_response",
        "verified_output",
    ]

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("=" * 70)
    print("NORMALISED MASTER DATASET COMPLETE")
    print("=" * 70)
    print(f"Valid logs processed : {len(rows)}")
    print(f"Columns created      : {len(fieldnames)}")
    print(f"Dataset saved to     : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
