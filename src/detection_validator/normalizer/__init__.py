"""
Normalizer — canonical schema and format converters.

All parsers produce dicts; the normalizer coerces them into typed
``DetectionRule`` Pydantic models so the rest of the pipeline has a
stable interface regardless of source format.
"""

from __future__ import annotations
