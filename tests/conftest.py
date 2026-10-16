import os
from pathlib import Path

os.environ.setdefault("DAC_ROOT", str(Path(__file__).resolve().parents[1]))
