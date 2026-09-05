"""Source-checkout import shim for ``python -m naos_governance.*``.

The packaged distribution maps the repository root to the ``naos_governance``
package. A source checkout executed from that same root needs this lightweight
package path so module entry points resolve without installation.
"""

from pathlib import Path

__version__ = "1.1.0"

_SOURCE_ROOT = Path(__file__).resolve().parent.parent
_source_root = str(_SOURCE_ROOT)
if _source_root not in __path__:
    __path__.append(_source_root)

__all__ = ["__version__"]
