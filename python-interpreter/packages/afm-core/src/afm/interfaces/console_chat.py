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

import asyncio
import json
import logging
import uuid
from typing import TYPE_CHECKING

from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.theme import Theme

if TYPE_CHECKING:
    from ..runner import AgentRunner

from ..runner import (
    PermissionRequestEvent,
    TokenEvent,
    ToolCallEvent,
    ToolResultEvent,
    TurnCompleteEvent,
)

logger = logging.getLogger(__name__)

_THEME = Theme(
    {
        "prompt": "bold",
        "dim": "dim",
        "err": "bold red",
    }
)


def _extract_tool_text(raw: str) -> str:
    """Extract human-readable text from MCP tool result format."""
    try:
        parsed = json.loads(raw.replace("'", '"'))
        if isinstance(parsed, list):
            texts = [
                item["text"] for item in parsed
                if isinstance(item, dict) and "text" in item
            ]
            if texts:
                return "\n".join(texts)
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
    return raw


class ConsoleChatREPL:
    """Interactive REPL for chatting with an AFM agent."""

    def __init__(
        self,
        agent: AgentRunner,
        session_id: str | None = None,
        update_notification: str | None = None,
    ):
        self.agent = agent
        self.session_id = session_id or str(uuid.uuid4())
        self._update_notification = update_notification
        self.console = Console(theme=_THEME)

    def _print_banner(self) -> None:
        self.console.print()
        self.console.print(f"[bold]{escape(self.agent.name)}[/bold]", highlight=False)
        if self.agent.description:
            self.console.print(
                f"[dim]{escape(self.agent.description)}[/dim]", highlight=False
            )
        self.console.print()
        self.console.print(
            "[dim]Type a message to chat. Use /help for commands, /quit to exit.[/dim]"
        )
        self.console.print()

    def _show_help(self) -> None:
        self.console.print()
        self.console.print("[bold]Commands[/bold]")
        self.console.print("  [bold]/help[/bold]   Show this help message")
        self.console.print("  [bold]/clear[/bold]  Clear conversation history")
        self.console.print("  [bold]/quit[/bold]   Exit the session")
        self.console.print()

    def _handle_command(self, user_input: str) -> bool:
        """Handle a slash command. Returns True if the REPL should exit."""
        cmd = user_input.lower().split()[0]
        if cmd in ("/quit", "/exit"):
            return True
        if cmd == "/help":
            self._show_help()
        elif cmd == "/clear":
            self.agent.clear_history(self.session_id)
            self.console.print("[dim]Conversation history cleared.[/dim]")
            self.console.print()
        else:
            self.console.print(f"[err]Unknown command: {escape(cmd)}[/err]")
            self.console.print("[dim]Type /help for available commands.[/dim]")
            self.console.print()
        return False

    async def run(self) -> None:
        self._print_banner()

        if self._update_notification:
            self.console.print(
                f"[yellow]{escape(self._update_notification)}[/yellow]"
            )
            self.console.print()

        loop = asyncio.get_running_loop()

        while True:
            try:
                user_input = await loop.run_in_executor(
                    None, lambda: self.console.input("[prompt]>[/prompt] ")
                )
            except (EOFError, KeyboardInterrupt):
                self.console.print()
                break

            user_input = user_input.strip()
            if not user_input:
                continue

            if user_input.startswith("/"):
                if self._handle_command(user_input):
                    break
                continue

            # Stream agent response
            self.console.print()
            try:
                has_tokens = False
                async for event in self.agent.astream(
                    user_input, session_id=self.session_id
                ):
                    match event:
                        case TokenEvent(text=chunk):
                            # Print raw token chunks inline
                            self.console.print(chunk, end="", highlight=False)
                            has_tokens = True

                        case ToolCallEvent(
                            tool_name=name, server_name=server
                        ):
                            label = (
                                f"{server}.{name}" if server else name
                            )
                            self.console.print(
                                f"  [dim]⏺ {escape(label)}[/dim]"
                            )

                        case ToolResultEvent(is_error=True, result=result):
                            text = _extract_tool_text(result)
                            self.console.print(
                                f"  [err]✗ {escape(text)}[/err]"
                            )

                        case ToolResultEvent(result=result):
                            text = _extract_tool_text(result)
                            preview = text[:200]
                            if len(text) > 200:
                                preview += "..."
                            self.console.print(
                                f"  [dim]✓ {escape(preview)}[/dim]"
                            )

                        case PermissionRequestEvent(
                            call_id=cid,
                            tool_name=name,
                            server_name=server,
                            arguments=args,
                        ):
                            label = (
                                f"{server}.{name}" if server else name
                            )
                            self.console.print(
                                f"  [bold]⏺ {escape(label)}[/bold]"
                            )
                            if args:
                                self.console.print(
                                    f"    [dim]{escape(str(args))}[/dim]"
                                )
                            answer = await loop.run_in_executor(
                                None,
                                lambda: self.console.input(
                                    "  Allow? [bold]\\[Y/n][/bold] "
                                ),
                            )
                            approved = answer.strip().lower() in (
                                "",
                                "y",
                                "yes",
                            )
                            if approved:
                                await self.agent.approve(cid)
                            else:
                                await self.agent.deny(
                                    cid, "User denied execution"
                                )

                        case TurnCompleteEvent(final_text=text):
                            if has_tokens:
                                # Tokens were already printed inline
                                self.console.print()
                            elif text:
                                self.console.print(Markdown(text))

            except Exception as e:
                logger.exception("Agent error")
                self.console.print(f"[err]Error: {escape(str(e))}[/err]")

            self.console.print()


async def async_run_console_chat(
    agent: AgentRunner,
    *,
    session_id: str | None = None,
) -> None:
    from ..update import get_update_notification

    update_msg = get_update_notification()
    repl = ConsoleChatREPL(
        agent, session_id=session_id, update_notification=update_msg
    )
    await repl.run()
