import logging
from mlslicer.main import main as run_pipeline
from mlslicer.checks import check_environment, check_inputs

logger = logging.getLogger(__name__)

def run_slicer(input_path: str, output_dir: str, verbose: bool = False, debug: bool = False):
    """Run the slicer pipeline on a single input file.

    Args:
        input_path: Path to the input source file to analyze.
        output_dir: Directory where outputs and artifacts are written.
        verbose: Enable INFO-level logging when True; otherwise use a higher threshold.
        **kwargs: Additional keyword arguments forwarded to the pipeline.
    """
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.ERROR
    logging.basicConfig(
        level=level,
        format="%(levelname)s | %(name)s | %(message)s"
    )
    check_environment()
    check_inputs(input_path, output_dir)
    run_pipeline(input_path, output_dir, verbose=verbose)
