import logging

try:
    # Python 3.9+
    from importlib.resources import files
except ImportError:
    # Python 3.8 fallback
    from importlib_resources import files
from pathlib import Path

logger = logging.getLogger(__name__)


class Config:
    def __init__(self, inference_path: Path, output_flag: bool) -> None:
        self.inference_path = inference_path
        self.output_flag = output_flag


# Resolve pyright path INSIDE the installed package
PYRIGHT_INDEX = (
    files("mlslicer")
    .joinpath("tools/pyright/packages/pyright/index.js")
)

configs = Config(Path(PYRIGHT_INDEX), True)
