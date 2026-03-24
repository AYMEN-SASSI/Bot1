"""
BotGeek - Core Tool Executor
Handles safe subprocess execution of Parrot OS security tools.
"""

import subprocess
import shlex
import logging
import time
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger("botgeek.executor")


@dataclass
class ExecutionResult:
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration: float
    success: bool


class ToolExecutor:
    """
    Safe, logged executor for Parrot OS security tools.
    Runs commands as subprocesses with timeout protection.
    """

    DEFAULT_TIMEOUT = 120  # seconds

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def run(
        self,
        cmd: str,
        timeout: Optional[int] = None,
        capture_stderr: bool = True,
    ) -> ExecutionResult:
        """
        Execute a shell command and return structured result.
        """
        effective_timeout = timeout or self.timeout
        start = time.time()

        logger.info(f"[Executor] Running: {cmd}")

        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
                timeout=effective_timeout,
            )
            duration = time.time() - start
            stdout = proc.stdout.decode(errors="replace")
            stderr = proc.stderr.decode(errors="replace") if capture_stderr else ""

            result = ExecutionResult(
                command=cmd,
                stdout=stdout,
                stderr=stderr,
                returncode=proc.returncode,
                duration=round(duration, 2),
                success=(proc.returncode == 0),
            )

            logger.info(
                f"[Executor] Finished in {result.duration}s | RC={result.returncode}"
            )
            return result

        except subprocess.TimeoutExpired:
            duration = time.time() - start
            logger.warning(f"[Executor] Timeout after {duration:.1f}s: {cmd}")
            return ExecutionResult(
                command=cmd,
                stdout="",
                stderr=f"Command timed out after {effective_timeout}s",
                returncode=-1,
                duration=round(duration, 2),
                success=False,
            )

        except Exception as exc:
            duration = time.time() - start
            logger.error(f"[Executor] Error: {exc}")
            return ExecutionResult(
                command=cmd,
                stdout="",
                stderr=str(exc),
                returncode=-1,
                duration=round(duration, 2),
                success=False,
            )

    def tool_available(self, tool_name: str) -> bool:
        """Check whether a CLI tool is installed on the system."""
        result = self.run(f"which {shlex.quote(tool_name)}", timeout=5)
        return result.success and bool(result.stdout.strip())
