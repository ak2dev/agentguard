import sys

hint = "pip install plot-helper"
try:
    import plot_helper  # noqa: F401
except ImportError:
    sys.exit(f"plot-helper is missing. Install it with `{hint}`.")
