# llm/constants.py
"""Shared constants for the LLM module — avoids circular imports between mixins."""

# Error message constants (SonarCloud: avoid duplicate literals)
MSG_OFFLINE_NO_KEY = "[Offline Mode] No API key configured."
MSG_OFFLINE_NO_CONN = "[Offline] No internet connection."
MSG_RATE_LIMITED = "[Rate Limited] Too many requests, please wait."
