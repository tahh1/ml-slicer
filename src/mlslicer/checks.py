import shutil
import os
import logging

logger = logging.getLogger(__name__)

def check_environment():
    if shutil.which("souffle") is None:
        raise RuntimeError("Soufflé not found on PATH")

    if shutil.which("node") is None:
        raise RuntimeError("Node.js not found on PATH")


from pathlib import Path


def check_inputs(input_path: str, output_dir: str) -> None:
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    

    if not input_path.exists():
        raise FileNotFoundError(f"Input path does not exist: {input_path}")

    if not input_path.is_file():
        raise ValueError(f"Input path is not a file: {input_path}")
    
    if str(input_path).endswith(".py") is False:
        logger.error("Input file is not a Python file: %s", input_path)
        raise ValueError(f"Input file is not a Python file: {input_path}")

    if output_dir.exists() and not output_dir.is_dir():
        raise NotADirectoryError(
            f"Output path exists but is not a directory: {output_dir}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        test_file = output_dir / ".write_test"
        test_file.touch(exist_ok=True)
        test_file.unlink()
    except Exception as e:
        raise PermissionError(
            f"Output directory is not writable: {output_dir}"
        ) from e
