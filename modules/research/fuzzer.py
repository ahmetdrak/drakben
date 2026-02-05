"""DRAKBEN Surgical Strike - Smart Fuzzer
Author: @drak_ben
Description: AI-guided mutation fuzzer for vulnerability discovery.
"""

import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# FUZZER CONSTANTS
# =============================================================================

# Mutation settings
DEFAULT_FUZZ_ITERATIONS = 1000
DEFAULT_BINARY_ITERATIONS = 100
DEFAULT_ENDPOINT_ITERATIONS = 100
DEFAULT_EMPTY_INPUT_SIZE = 100

# Probability thresholds (out of 3 for ~33%)
MUTATION_PROBABILITY = 3  # 1 in 3 chance
MAGIC_VALUE_PROBABILITY = 10  # 4 in 10 (40%)
MAGIC_VALUE_THRESHOLD = 4

# Crash detection
MAX_CRASHES_TO_COLLECT = 10


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

    def fuzz_function(
        self,
        target_func: Callable,
        seed_inputs: list[Any],
        iterations: int = DEFAULT_FUZZ_ITERATIONS,
    ) -> list[FuzzResult]:
        """Fuzz a Python function directly."""
        crashes = []
        logger.info(
            f"Starting Fuzzing Session on {target_func.__name__} ({iterations} iterations)",
        )

        for i in range(iterations):
            # Select seed
            seed = secrets.choice(seed_inputs)

            # Mutate
            fuzz_input: str | bytes | int
            if isinstance(seed, str):
                fuzz_input = self.mutate(seed.encode()).decode(
                    "latin-1",
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
                logger.warning(f"CRASH DETECTED at iter {i}: %s", e)
                crashes.append(crash_info)

                # Stop if too many crashes to avoid flooding
                if len(crashes) > MAX_CRASHES_TO_COLLECT:
                    break

        logger.info("Fuzzing completed. Found %s unique crashes.", len(crashes))
        return crashes

    def fuzz_binary(
        self,
        binary_path: str,
        seed_inputs: list[bytes],
        iterations: int = DEFAULT_BINARY_ITERATIONS,
        timeout: float = 5.0,
        args_template: list[str] | None = None,
    ) -> list[FuzzResult]:
        """Fuzz a binary executable with mutated inputs.

        Args:
            binary_path: Path to the binary to fuzz
            seed_inputs: List of seed input bytes to mutate
            iterations: Number of fuzzing iterations
            timeout: Timeout per execution in seconds
            args_template: Command line args template (use {INPUT} for fuzz data)

        Returns:
            List of FuzzResult for crashes detected

        """
        import subprocess
        import tempfile

        crashes = []
        logger.info(f"Starting Binary Fuzzing on {binary_path} ({iterations} iterations)")

        for i in range(iterations):
            # Select and mutate seed
            seed = secrets.choice(seed_inputs)
            fuzz_data = self.mutate(seed)

            # Write to temp file for binary input
            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
                tmp.write(fuzz_data)
                tmp_path = tmp.name

            try:
                # Build command
                if args_template:
                    cmd = [binary_path] + [
                        arg.replace("{INPUT}", tmp_path) for arg in args_template
                    ]
                else:
                    cmd = [binary_path, tmp_path]

                start_time = time.time()
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout,
                    check=False,
                )
                exec_time = time.time() - start_time

                # Detect crashes (segfault, abort, etc.)
                if result.returncode < 0 or result.returncode > 128:
                    crash_info = FuzzResult(
                        input_data=fuzz_data,
                        crash_detected=True,
                        error_message=f"Exit code: {result.returncode}",
                        execution_time=exec_time,
                    )
                    logger.warning(f"CRASH at iter {i}: exit code {result.returncode}")
                    crashes.append(crash_info)

            except subprocess.TimeoutExpired:
                logger.debug(f"Timeout at iteration {i}")
            except Exception as e:
                logger.debug(f"Execution error: {e}")
            finally:
                # Cleanup temp file
                try:
                    import os
                    os.unlink(tmp_path)
                except OSError as e:
                    logger.debug("Failed to cleanup temp file %s: %s", tmp_path, e)

            if len(crashes) > MAX_CRASHES_TO_COLLECT:
                break

        logger.info(f"Binary fuzzing completed. Found {len(crashes)} crashes.")
        return crashes

    async def fuzz_endpoint(
        self,
        url: str,
        method: str = "POST",
        seed_payloads: list[str] | None = None,
        iterations: int = DEFAULT_ENDPOINT_ITERATIONS,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> list[FuzzResult]:
        """Fuzz an HTTP endpoint with mutated payloads.

        Args:
            url: Target URL to fuzz
            method: HTTP method (GET, POST, PUT, DELETE)
            seed_payloads: Seed payloads to mutate
            iterations: Number of fuzzing iterations
            headers: Custom HTTP headers
            timeout: Request timeout in seconds

        Returns:
            List of FuzzResult for interesting responses

        """
        import aiohttp

        results = []
        default_seeds = [
            '{"test": "value"}',
            '<xml>test</xml>',
            'param=value&other=test',
            'A' * 1000,
            '../../../etc/passwd',
            "' OR '1'='1",
        ]
        payloads = seed_payloads or default_seeds
        default_headers = {"Content-Type": "application/json"}
        req_headers = headers or default_headers

        logger.info(f"Starting Endpoint Fuzzing on {url} ({iterations} iterations)")

        async with aiohttp.ClientSession() as session:
            for i in range(iterations):
                # Mutate payload
                seed = secrets.choice(payloads)
                fuzz_payload = self.mutate(seed.encode()).decode("latin-1")

                start_time = time.time()
                try:
                    async with session.request(
                        method,
                        url,
                        data=fuzz_payload,
                        headers=req_headers,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,  # noqa: S501 - Security tool testing self-signed certs
                    ) as response:
                        exec_time = time.time() - start_time
                        status = response.status

                        # Interesting responses: 500 errors, unusual status codes
                        if status >= 500 or status in [400, 403, 405]:
                            body = await response.text()
                            result = FuzzResult(
                                input_data=fuzz_payload,
                                crash_detected=status >= 500,
                                error_message=f"HTTP {status}: {body[:200]}",
                                execution_time=exec_time,
                            )
                            results.append(result)
                            logger.warning(f"Interesting response at iter {i}: HTTP {status}")

                except aiohttp.ClientError as e:
                    exec_time = time.time() - start_time
                    results.append(FuzzResult(
                        input_data=fuzz_payload,
                        crash_detected=False,
                        error_message=f"Connection error: {e}",
                        execution_time=exec_time,
                    ))
                except Exception as e:
                    logger.debug(f"Request error: {e}")

                if len(results) > 20:
                    break

        logger.info(f"Endpoint fuzzing completed. Found {len(results)} interesting responses.")
        return results
