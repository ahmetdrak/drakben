"""DRAKBEN Surgical Strike - Smart Fuzzer
Author: @drak_ben
Description: AI-guided mutation fuzzer for vulnerability discovery.
"""

import logging
import secrets
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# FUZZER CONSTANTS
# =============================================================================

# Mutation settings
DEFAULT_EMPTY_INPUT_SIZE = 100

# Probability thresholds (out of 3 for ~33%)
MAGIC_VALUE_PROBABILITY = 10  # 4 in 10 (40%)
MAGIC_VALUE_THRESHOLD = 4


@dataclass
class FuzzResult:
    """Result of a single fuzz test iteration.

    Attributes:
        input_data: The mutated input that was tested
        crash_detected: Whether the input caused a crash/error
        error_message: Error details if crash occurred
        execution_time: Time taken to execute the test (seconds)
    """

    input_data: Any
    crash_detected: bool
    error_message: str = ""
    execution_time: float = 0.0


class SmartFuzzer:
    """Mutation-based fuzzer with heuristic strategies."""

    def __init__(self) -> None:
        self.magic_values: list[int | str] = [
            0,
            1,
            -1,
            255,
            256,
            65535,
            65536,
            2**31 - 1,
            2**32,
            2**64 - 1,
            "A" * 10,
            "A" * 100,
            "A" * 1000,
            "A" * 5000,
            "%s",
            "%x",
            "%n",  # Format string
            "../../../etc/passwd",  # Path traversal
            "<script>alert(1)</script>",  # XSS
            "' OR '1'='1",  # SQLi
        ]
        logger.info("Smart Fuzzer initialized")

    def mutate(self, data: bytes, _aggressiveness: float = 0.1) -> bytes:
        """Apply random mutations to input data."""
        mutable_data = bytearray(data)
        length = len(mutable_data)
        if length == 0:
            return b"A" * DEFAULT_EMPTY_INPUT_SIZE

        # Strategy 1: Bit Flip (~33% chance)
        if secrets.choice([True, False, False]):
            pos = secrets.randbelow(length)
            bit = secrets.randbelow(8)
            mutable_data[pos] ^= 1 << bit

        # Strategy 2: Byte Flip (~33% chance)
        if secrets.choice([True, False, False]):
            pos = secrets.randbelow(length)
            mutable_data[pos] = secrets.randbelow(256)

        # Strategy 3: Magic Value Injection (40% chance)
        if secrets.randbelow(MAGIC_VALUE_PROBABILITY) < MAGIC_VALUE_THRESHOLD:
            magic = str(secrets.choice(self.magic_values)).encode()
            if len(magic) < length:
                pos = secrets.randbelow(length - len(magic) + 1)
                mutable_data[pos : pos + len(magic)] = magic
            else:
                mutable_data = bytearray(magic)  # Replace completely

        return bytes(mutable_data)

