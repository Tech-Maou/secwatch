"""Safe subprocess execution (never shell=True) with timeouts."""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
from dataclasses import dataclass

log = logging.getLogger(__name__)


class ToolError(RuntimeError):
    pass


@dataclass
class Result:
    rc: int
    stdout: str
    stderr: str


def which(name: str) -> str | None:
    return shutil.which(name)


def run(cmd: list[str], timeout: float = 600, env: dict | None = None, ok_codes: tuple[int, ...] = (0,),
        cwd: str | None = None, input_text: str | None = None) -> Result:
    if not cmd or not isinstance(cmd, list) or not all(isinstance(c, str) for c in cmd):
        raise ToolError("invalid command")
    exe = which(cmd[0]) if os.sep not in cmd[0] else cmd[0]
    if not exe:
        raise ToolError(f"{cmd[0]} not found on PATH")
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    log.debug("run: %s", " ".join(cmd))
    try:
        p = subprocess.Popen([exe, *cmd[1:]], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                             env=full_env, cwd=cwd, text=True, start_new_session=True)
    except OSError as e:
        raise ToolError(f"cannot start {cmd[0]}: {e}") from e
    try:
        out, err = p.communicate(input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            p.kill()
        p.communicate()
        raise ToolError(f"{cmd[0]} timed out after {int(timeout)} s")
    if p.returncode not in ok_codes:
        tail = (err or out or "").strip().splitlines()[-3:]
        raise ToolError(f"{cmd[0]} exited with {p.returncode}: {' | '.join(tail)[:400]}")
    return Result(p.returncode, out, err)
