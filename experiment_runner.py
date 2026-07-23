"""
experiment_runner.py

Master experiment controller for the MSc project:

Security Evaluation of LLM-Based Autonomous Agents:
Mapping Tool-Use Behaviours to MITRE ATT&CK

Author: Akshay Rana
"""

import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

SCENARIOS = [
    ("Scenario 01 - File Discovery",
     PROJECT_ROOT / "scenarios/scenario_01_file_discovery/agent.py"),

    ("Scenario 02 - Command Execution",
     PROJECT_ROOT / "scenarios/scenario_02_command_execution/scenario.py"),

    ("Scenario 03 - System Information",
     PROJECT_ROOT / "scenarios/scenario_03_system_information/scenario.py"),

    ("Scenario 04 - Secure API Interaction",
     PROJECT_ROOT / "scenarios/scenario_04_secure_api_interaction/scenario.py"),

    ("Scenario 05 - Prompt Injection",
     PROJECT_ROOT / "scenarios/scenario_05_prompt_injection/scenario.py"),
]

successful = 0
failed = 0

print("=" * 70)
print("LLM AGENT SECURITY EVALUATION")
print("=" * 70)

overall_start = time.perf_counter()

for name, script in SCENARIOS:

    print(f"\n{name}")
    print("-" * 70)

    start = time.perf_counter()

    result = subprocess.run(
        [sys.executable, str(script)]
    )

    elapsed = time.perf_counter() - start

    if result.returncode == 0:
        successful += 1
        print(f"✓ SUCCESS ({elapsed:.2f} seconds)")
    else:
        failed += 1
        print(f"✗ FAILED ({elapsed:.2f} seconds)")

overall_time = time.perf_counter() - overall_start

print("\n" + "=" * 70)
print("EXPERIMENT SUMMARY")
print("=" * 70)

print(f"Successful scenarios : {successful}")
print(f"Failed scenarios     : {failed}")
print(f"Total scenarios      : {len(SCENARIOS)}")
print(f"Execution time       : {overall_time:.2f} seconds")
