import subprocess
import sys
import time


NUMBER_OF_RUNS = 5
SCENARIO_PROGRAM = "scenario_01_agent.py"


def main():

    print("\n===== SCENARIO 01 EXPERIMENT RUNNER =====")

    successful_runs = 0
    failed_runs = 0

    for run_number in range(1, NUMBER_OF_RUNS + 1):

        print(
            f"\n===== STARTING RUN "
            f"{run_number}/{NUMBER_OF_RUNS} ====="
        )

        start_time = time.perf_counter()

        completed_process = subprocess.run(
            [
                sys.executable,
                SCENARIO_PROGRAM,
            ],
            check=False,
        )

        duration_seconds = (
            time.perf_counter() - start_time
        )

        if completed_process.returncode == 0:
            successful_runs += 1

            print(
                f"RUN {run_number} COMPLETED "
                f"IN {duration_seconds:.2f} SECONDS"
            )

        else:
            failed_runs += 1

            print(
                f"RUN {run_number} FAILED "
                f"WITH EXIT CODE "
                f"{completed_process.returncode}"
            )

        if run_number < NUMBER_OF_RUNS:
            print("Waiting 2 seconds before next run...")
            time.sleep(2)

    print("\n===== EXPERIMENT BATCH COMPLETE =====")

    print("Requested runs:", NUMBER_OF_RUNS)
    print("Successful runs:", successful_runs)
    print("Failed runs:", failed_runs)


if __name__ == "__main__":
    main()
