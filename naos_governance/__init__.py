"""Source-checkout import shim for ``python -m naos_governance.*``.

The packaged distribution maps the repository root to the ``naos_governance``
package. A source checkout executed from that same root needs this lightweight
package path so module entry points resolve without installation.
"""

from pathlib import Path
from runpy import run_path

_SOURCE_ROOT = Path(__file__).resolve().parent.parent
__version__ = run_path(str(_SOURCE_ROOT / "__init__.py"))["__version__"]
_source_root = str(_SOURCE_ROOT)
if _source_root not in __path__:
    __path__.append(_source_root)

__all__ = ["__version__"]
