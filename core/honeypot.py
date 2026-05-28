from __future__ import annotations

from pathlib import Path
from typing import List


def generate_honey_files(
    honey_dir: Path,
    honey_files: list[str],
    default_content: str,
    overwrite: bool = False,
) -> List[Path]:
    """
    Create honey token files in the chosen directory.
    """

    honey_dir.mkdir(parents=True, exist_ok=True)

    created_paths: List[Path] = []

    for filename in honey_files:
        file_path = honey_dir / filename

        if file_path.exists() and not overwrite:
            continue

        file_path.write_text(default_content, encoding="utf-8")
        created_paths.append(file_path)

    return created_paths