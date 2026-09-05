"""Allow `python -m naos_governance` to work."""

import sys

from .cli import main

sys.exit(main())
