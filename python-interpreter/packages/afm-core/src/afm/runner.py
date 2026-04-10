# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

from __future__ import annotations

import importlib.metadata
import logging
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Protocol, runtime_checkable

from .models import AFMRecord, Signature

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "afm.runner"
DEFAULT_RUNNER = "langchain"


# ---------------------------------------------------------------------------
# Agent event types — used by astream() to communicate incremental progress
# ---------------------------------------------------------------------------


@dataclass
class AgentEvent:
    """Base class for events yielded during an agent turn."""


@dataclass
class TokenEvent(AgentEvent):
    """A chunk of LLM-generated text."""

    text: str


@dataclass
class ToolCallEvent(AgentEvent):
    """The agent is about to call a tool."""

    call_id: str
    tool_name: str
    server_name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResultEvent(AgentEvent):
    """A tool call completed."""

    call_id: str
    result: str
    is_error: bool = False


@dataclass
class PermissionRequestEvent(AgentEvent):
    """The agent needs user approval before executing a tool call.

    The UI must call runner.approve(call_id) or runner.deny(call_id)
    to unblock execution.
    """

    call_id: str
    tool_name: str
    server_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass
class TurnCompleteEvent(AgentEvent):
    """The agent turn is finished."""

    final_text: str | None = None


@runtime_checkable
class AgentRunner(Protocol):
    """Protocol that all AFM execution backends must implement."""

    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str | None: ...

    @property
    def afm(self) -> AFMRecord: ...

    @property
    def signature(self) -> Signature: ...

    async def connect(self) -> None: ...
    async def disconnect(self) -> None: ...

    async def arun(
        self,
        input_data: str | dict[str, Any],
        *,
        session_id: str = "default",
    ) -> str | dict[str, Any]: ...

    def astream(
        self,
        input_data: str | dict[str, Any],
        *,
        session_id: str = "default",
    ) -> AsyncIterator[AgentEvent]: ...

    async def approve(self, call_id: str) -> None: ...
    async def deny(self, call_id: str, reason: str = "") -> None: ...

    def clear_history(self, session_id: str = "default") -> None: ...

    async def __aenter__(self) -> AgentRunner: ...
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None: ...


def discover_runners() -> dict[str, importlib.metadata.EntryPoint]:
    """Scan for installed backends via entry points."""
    eps = importlib.metadata.entry_points()
    runners: dict[str, importlib.metadata.EntryPoint] = {}

    # entry_points() returns a SelectableGroups or dict-like depending on Python version
    group_eps = eps.select(group=ENTRY_POINT_GROUP)
    for ep in group_eps:
        runners[ep.name] = ep

    return runners


def load_runner(name: str | None = None) -> type[AgentRunner]:
    """Load a specific runner by name, or the default/first available one.

    Args:
        name: The name of the runner entry point. If None, the default
              runner (langchain) is used if available, otherwise the first
              available runner is returned.

    Returns:
        The runner class (not an instance).

    Raises:
        RuntimeError: If no runner is found or the specified name doesn't exist.
    """
    runners = discover_runners()

    if len(runners) == 0:
        from afm.update import _detect_install_command

        install_cmd = _detect_install_command("afm-langchain")
        if install_cmd is None:
            hint = "Use a container image that includes 'afm-langchain'."
        else:
            hint = (
                "Install a backend package such as 'afm-langchain':\n\n"
                f"  {install_cmd}\n"
            )
        raise RuntimeError(f"No AFM runner backends found. {hint}")

    if name is not None:
        if name not in runners:
            available = ", ".join(sorted(runners.keys()))
            raise RuntimeError(
                f"Runner '{name}' not found. Available runners: {available}"
            )
        ep = runners[name]
    else:
        # Prefer the default runner, fall back to the first available
        ep = runners.get(DEFAULT_RUNNER) or next(iter(runners.values()))

    runner_cls = ep.load()
    logger.info(f"Loaded runner: {ep.name} ({ep.value})")
    return runner_cls
