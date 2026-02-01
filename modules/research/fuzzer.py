"""
DRAKBEN Surgical Strike - Smart Fuzzer
Author: @drak_ben
Description: AI-guided mutation fuzzer for vulnerability discovery.
"""

import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any
from collections.abc import Callable

logger = logging.getLogger(__name__)


@dataclass
class FuzzResult:
    input_data: Any
    crash_detected: bool
    error_message: str = ""
    execution_time: float = 0.0


class SmartFuzzer:
    """
    Mutation-based fuzzer with heuristic strategies.
    """

    def __init__(self):
        self.magic_values = [
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
        """
        Apply random mutations to input data.
        """
        mutable_data = bytearray(data)
        length = len(mutable_data)
        if length == 0:
            return b"A" * 100

        # Strategy 1: Bit Flip
        if secrets.choice([True, False, False]):  # ~33% chance (approx 0.3)
            pos = secrets.randbelow(length)
            bit = secrets.randbelow(8)
            mutable_data[pos] ^= 1 << bit

        # Strategy 2: Byte Flip
        if secrets.choice([True, False, False]):  # ~33% chance
            pos = secrets.randbelow(length)
            mutable_data[pos] = secrets.randbelow(256)

        # Strategy 3: Magic Value Injection (Overlay)
        if secrets.randbelow(10) < 4:  # 40% chance
            magic = str(secrets.choice(self.magic_values)).encode()
            if len(magic) < length:
                pos = secrets.randbelow(length - len(magic) + 1)
                mutable_data[pos : pos + len(magic)] = magic
            else:
                mutable_data = magic  # Replace completely

        return bytes(mutable_data)

    def fuzz_function(
        self, target_func: Callable, seed_inputs: list[Any], iterations: int = 1000
    ) -> list[FuzzResult]:
        """
        Fuzz a Python function directly.
        """
        crashes = []
        logger.info(
            f"Starting Fuzzing Session on {target_func.__name__} ({iterations} iterations)"
        )

        for i in range(iterations):
            # Select seed
            seed = secrets.choice(seed_inputs)

            # Mutate
            if isinstance(seed, str):
                fuzz_input = self.mutate(seed.encode()).decode(
                    "latin-1"
                )  # Decode to keep as str
            elif isinstance(seed, bytes):
                fuzz_input = self.mutate(seed)
            else:
                # For non-bytes, try to cast or inject raw values
                fuzz_input = secrets.choice(self.magic_values)

            # Execute
            start_time = time.time()
            try:
                target_func(fuzz_input)
                # No crash
            except Exception as e:
                exec_time = time.time() - start_time
                crash_info = FuzzResult(
                    input_data=fuzz_input,
                    crash_detected=True,
                    error_message=str(e),
                    execution_time=exec_time,
                )
                logger.warning(f"CRASH DETECTED at iter {i}: {e}")
                crashes.append(crash_info)

                # Stop if too many crashes to avoid flooding
                if len(crashes) > 10:
                    break

        logger.info(f"Fuzzing completed. Found {len(crashes)} unique crashes.")
        return crashes
