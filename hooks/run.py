"""Runs a spillage hook straight from the plugin folder.

spillage has no dependencies, so the plugin needs nothing installed but Python: this puts the
folder it was downloaded to on the import path and hands over to `spillage hook <event>`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from spillage.cli import main

if __name__ == "__main__":
    sys.exit(main(["hook", *sys.argv[1:]]))
