"""
Autoresearch evaluator extension namespace.

The portable kit currently ships deterministic conformance review plus
deterministic audit/drift/assess review-input modes in ``autoresearch/runner.py``.
LLM-backed judging and composite scoring remain future/project-configured work.

This package exposes the deterministic StaticGrader foundation. Behavioral,
semantic, provider-backed, composite, and LLM judging remain
future/project-configured work.
"""

from .base import BaseGrader
from .static import StaticGrader

__all__ = ["BaseGrader", "StaticGrader"]
