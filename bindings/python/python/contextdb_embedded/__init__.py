"""Embedded, in-process ContextDB binding.

The transport-neutral JSON methods intentionally use the exact canonical
service schema. For a Pythonic remote client and agent middleware, use the
separate ``contextdb`` HTTP SDK under ``sdk/python``.
"""

from ._contextdb import ContextDb

__all__ = ["ContextDb"]
