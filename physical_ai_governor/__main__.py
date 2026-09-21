"""
Executable entrypoint for `python3 -m physical_ai_governor`.
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
