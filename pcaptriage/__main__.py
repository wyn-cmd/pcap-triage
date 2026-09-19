"""Run the tool with python3 -m pcaptriage, which is how the docs call it."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
