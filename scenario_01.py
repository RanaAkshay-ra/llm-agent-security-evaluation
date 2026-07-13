from pathlib import Path
from langchain_core.tools import tool

SANDBOX_DIRECTORY = Path(
    "/agent_project/scenarios/scenario_01_file_discovery/test_files"
)


@tool
def list_test_files() -> str:
    """List files inside the authorised experimental directory."""

    files = sorted(
        item.name
        for item in SANDBOX_DIRECTORY.iterdir()
        if item.is_file()
    )

    return "\n".join(files)


print(list_test_files.invoke({}))
