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

from io import StringIO
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from rich.console import Console

from afm.interfaces.console_chat import ConsoleChatREPL
from afm.runner import (
    AgentRunner,
    PermissionRequestEvent,
    TokenEvent,
    ToolCallEvent,
    ToolResultEvent,
    TurnCompleteEvent,
)


async def _make_stream(*events):
    """Helper to create an async iterator of AgentEvents."""
    for event in events:
        yield event


@pytest.fixture
def mock_agent() -> MagicMock:
    agent = MagicMock(spec=AgentRunner)
    agent.name = "Test Agent"
    agent.description = "A test agent for unit testing"
    agent.astream = MagicMock(
        return_value=_make_stream(
            TokenEvent(text="Hello! I'm the test agent."),
            TurnCompleteEvent(final_text="Hello! I'm the test agent."),
        )
    )
    agent.clear_history = MagicMock()
    agent.approve = AsyncMock()
    agent.deny = AsyncMock()
    return agent


@pytest.fixture
def repl(mock_agent: MagicMock) -> ConsoleChatREPL:
    r = ConsoleChatREPL(mock_agent)
    r.console = Console(file=StringIO(), no_color=True, highlight=False)
    return r


def get_output(repl: ConsoleChatREPL) -> str:
    file = repl.console.file
    assert isinstance(file, StringIO)
    return file.getvalue()


@pytest.mark.asyncio
async def test_banner_shows_agent_info(repl: ConsoleChatREPL) -> None:
    repl._print_banner()
    output = get_output(repl)
    assert "Test Agent" in output
    assert "A test agent for unit testing" in output
    assert "/help" in output
    assert "/quit" in output


@pytest.mark.asyncio
async def test_help_command(repl: ConsoleChatREPL) -> None:
    repl._handle_command("/help")
    output = get_output(repl)
    assert "/help" in output
    assert "/clear" in output
    assert "/quit" in output


@pytest.mark.asyncio
async def test_clear_command(repl: ConsoleChatREPL, mock_agent: MagicMock) -> None:
    repl._handle_command("/clear")
    mock_agent.clear_history.assert_called_once_with(repl.session_id)
    output = get_output(repl)
    assert "cleared" in output.lower()


@pytest.mark.asyncio
async def test_quit_command(repl: ConsoleChatREPL) -> None:
    assert repl._handle_command("/quit") is True
    assert repl._handle_command("/exit") is True


@pytest.mark.asyncio
async def test_unknown_command(repl: ConsoleChatREPL) -> None:
    assert repl._handle_command("/unknown") is False
    output = get_output(repl)
    assert "Unknown command" in output


@pytest.mark.asyncio
async def test_user_message_flow(
    repl: ConsoleChatREPL, mock_agent: MagicMock
) -> None:
    inputs = iter(["Hello!", "/quit"])

    with patch.object(repl.console, "input", side_effect=inputs):
        await repl.run()

    mock_agent.astream.assert_called_once()
    call_args = mock_agent.astream.call_args
    assert call_args[0][0] == "Hello!"
    output = get_output(repl)
    assert "Hello! I'm the test agent." in output


@pytest.mark.asyncio
async def test_agent_error_display(
    repl: ConsoleChatREPL, mock_agent: MagicMock
) -> None:
    async def _error_stream(*args, **kwargs):
        raise Exception("Test Error")
        yield  # make it an async generator  # noqa: E501

    mock_agent.astream = MagicMock(side_effect=_error_stream)
    inputs = iter(["Hello", "/quit"])

    with patch.object(repl.console, "input", side_effect=inputs):
        await repl.run()

    output = get_output(repl)
    assert "Test Error" in output


@pytest.mark.asyncio
async def test_tool_call_display(
    repl: ConsoleChatREPL, mock_agent: MagicMock
) -> None:
    mock_agent.astream = MagicMock(
        return_value=_make_stream(
            ToolCallEvent(
                call_id="1", tool_name="read_file", server_name="filesystem"
            ),
            ToolResultEvent(call_id="1", result="file contents"),
            TokenEvent(text="I read the file."),
            TurnCompleteEvent(final_text="I read the file."),
        )
    )
    inputs = iter(["read it", "/quit"])

    with patch.object(repl.console, "input", side_effect=inputs):
        await repl.run()

    output = get_output(repl)
    assert "filesystem.read_file" in output
    assert "file contents" in output
    assert "I read the file." in output


@pytest.mark.asyncio
async def test_tool_error_display(
    repl: ConsoleChatREPL, mock_agent: MagicMock
) -> None:
    mock_agent.astream = MagicMock(
        return_value=_make_stream(
            ToolCallEvent(
                call_id="1", tool_name="run_cmd", server_name="shell"
            ),
            ToolResultEvent(
                call_id="1", result="Permission denied", is_error=True
            ),
            TurnCompleteEvent(final_text="The command failed."),
        )
    )
    inputs = iter(["do it", "/quit"])

    with patch.object(repl.console, "input", side_effect=inputs):
        await repl.run()

    output = get_output(repl)
    assert "shell.run_cmd" in output
    assert "Permission denied" in output


@pytest.mark.asyncio
async def test_empty_input_ignored(
    repl: ConsoleChatREPL, mock_agent: MagicMock
) -> None:
    inputs = iter(["", "  ", "/quit"])

    with patch.object(repl.console, "input", side_effect=inputs):
        await repl.run()

    mock_agent.astream.assert_not_called()


@pytest.mark.asyncio
async def test_eof_exits(repl: ConsoleChatREPL) -> None:
    with patch.object(repl.console, "input", side_effect=EOFError):
        await repl.run()


@pytest.mark.asyncio
async def test_keyboard_interrupt_exits(repl: ConsoleChatREPL) -> None:
    with patch.object(repl.console, "input", side_effect=KeyboardInterrupt):
        await repl.run()


@pytest.mark.asyncio
async def test_permission_approved(
    repl: ConsoleChatREPL, mock_agent: MagicMock
) -> None:
    mock_agent.astream = MagicMock(
        return_value=_make_stream(
            PermissionRequestEvent(
                call_id="1",
                tool_name="run_command",
                server_name="shell",
                arguments={"cmd": "rm -rf /tmp/old"},
                reason="Tool requires user confirmation",
            ),
            ToolResultEvent(call_id="1", result="done"),
            TurnCompleteEvent(final_text="Cleaned up."),
        )
    )
    # First input: user message, second: "y" for approval, third: /quit
    inputs = iter(["clean up", "y", "/quit"])

    with patch.object(repl.console, "input", side_effect=inputs):
        await repl.run()

    mock_agent.approve.assert_called_once_with("1")
    mock_agent.deny.assert_not_called()
    output = get_output(repl)
    assert "shell.run_command" in output


@pytest.mark.asyncio
async def test_permission_denied(
    repl: ConsoleChatREPL, mock_agent: MagicMock
) -> None:
    mock_agent.astream = MagicMock(
        return_value=_make_stream(
            PermissionRequestEvent(
                call_id="2",
                tool_name="run_command",
                server_name="shell",
                arguments={"cmd": "rm -rf /"},
                reason="Tool requires user confirmation",
            ),
            ToolResultEvent(
                call_id="2",
                result="User denied execution",
                is_error=True,
            ),
            TurnCompleteEvent(final_text="Operation cancelled."),
        )
    )
    inputs = iter(["delete everything", "n", "/quit"])

    with patch.object(repl.console, "input", side_effect=inputs):
        await repl.run()

    mock_agent.deny.assert_called_once_with("2", "User denied execution")
    mock_agent.approve.assert_not_called()
