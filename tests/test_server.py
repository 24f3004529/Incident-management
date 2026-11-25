"""Tests for the MCP server that exposes the IncidentResolution tools."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path
from typing import Any

import anyio
import pytest
from loguru import logger

from incident_mcp import IncidentResolution
from incident_mcp.server import SDK_MAJOR, create_server, discover_tools, main, parse_tool_doc

logger.remove()

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TOOLS = sorted(
    name for name, fn in inspect.getmembers(IncidentResolution, inspect.isfunction) if not name.startswith("_")
)


@pytest.fixture(scope="module")
def server() -> Any:
    return create_server()


def _structured(result: Any) -> dict[str, Any]:
    """Structured tool output, for both SDK 2.x (CallToolResult) and 1.x (content, structured) tuples."""
    if hasattr(result, "structured_content"):
        return result.structured_content
    if isinstance(result, tuple):
        return result[1]
    raise AssertionError(f"unexpected call_tool result: {result!r}")


def _dump(tool: Any) -> dict[str, Any]:
    return tool.model_dump(by_alias=True, exclude_none=True)


# ------------------------------------------------------------------ discovery


def test_every_tool_is_discovered() -> None:
    names = sorted(name for name, _, _ in discover_tools(IncidentResolution()))
    assert names == EXPECTED_TOOLS


def test_methods_not_exposed_via_mcp_are_skipped() -> None:
    def internal() -> None:
        """
        description:
            Not for agents.

        expose:
            - fastapi
        """

    def no_doc() -> None:
        pass

    def bad_yaml() -> None:
        """description: a: b: c"""

    assert parse_tool_doc(internal) is None
    assert parse_tool_doc(no_doc) is None
    assert parse_tool_doc(bad_yaml) is None


def test_handler_keeps_signature_and_defaults() -> None:
    tools = {name: handler for name, _, handler in discover_tools(IncidentResolution())}
    sig = inspect.signature(tools["assess_severity"])
    assert list(sig.parameters) == ["incident", "users_affected", "is_production", "revenue_impact"]
    assert sig.parameters["incident"].default is inspect.Parameter.empty
    assert sig.parameters["revenue_impact"].default is False
    assert tools["classify_incident"](incident="disk full")["category"] == "Disk"


# ------------------------------------------------------------------ tool listing


def test_list_tools_metadata(server: Any) -> None:
    tools = {t.name: _dump(t) for t in anyio.run(server.list_tools)}
    assert sorted(tools) == EXPECTED_TOOLS

    tool = tools["assess_severity"]
    assert tool["description"].startswith("Use this tool when the user asks how serious an incident is")
    schema = tool["inputSchema"]
    assert schema["required"] == ["incident"]
    assert schema["properties"]["incident"]["description"] == "Free-text description of the incident"
    assert schema["properties"]["revenue_impact"]["default"] is False

    annotations = tool["annotations"]
    assert annotations["readOnlyHint"] is True and annotations["destructiveHint"] is False
    assert annotations["idempotentHint"] is True and annotations["openWorldHint"] is False
    if SDK_MAJOR >= 2:
        assert tool["_meta"] == {"tags": ["incident", "severity"]}


@pytest.mark.parametrize("name", EXPECTED_TOOLS)
def test_every_argument_has_a_description(server: Any, name: str) -> None:
    tool = next(_dump(t) for t in anyio.run(server.list_tools) if t.name == name)
    for prop in tool["inputSchema"].get("properties", {}).values():
        assert prop.get("description"), f"{name} has an argument without description"


# ------------------------------------------------------------------ tool calls


def test_call_tool_returns_structured_result(server: Any) -> None:
    async def call() -> Any:
        return await server.call_tool("classify_incident", {"incident": "connection timeout calling payment API"})

    result = _structured(anyio.run(call))
    assert result["success"] is True and result["category"] == "Network"


def test_call_tool_with_list_and_optional_args(server: Any) -> None:
    async def call() -> Any:
        return await server.call_tool(
            "create_escalation_summary",
            {"incident": "Checkout API 500 errors, too many connections", "actions_taken": ["Restarted pods"],
             "severity": "SEV2", "minutes_open": 75},
        )

    result = _structured(anyio.run(call))
    assert result["team"] == "DBA Team" and result["tier"] == "L2"
    assert "- Restarted pods" in result["summary"]


def test_tool_level_errors_are_returned_not_raised(server: Any) -> None:
    async def call() -> Any:
        return await server.call_tool("classify_incident", {"incident": "   "})

    assert _structured(anyio.run(call)) == {"success": False, "error": "incident text is empty"}


def test_prompt_is_registered(server: Any) -> None:
    async def get() -> tuple[list[Any], Any]:
        prompts = await server.list_prompts()
        rendered = await server.get_prompt("incident_response", {"incident": "Disk full on app-01", "audience": "management"})
        return prompts, rendered

    prompts, rendered = anyio.run(get)
    assert [p.name for p in prompts] == ["incident_response"]
    text = rendered.messages[0].content.text
    assert "Disk full on app-01" in text and "create_executive_summary" in text


# ------------------------------------------------------------------ end to end over stdio


def test_stdio_end_to_end() -> None:
    from mcp import StdioServerParameters

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "incident_mcp.server", "--log-level", "WARNING"],
        cwd=str(ROOT),
    )

    async def run() -> tuple[list[str], dict[str, Any], bool]:
        with anyio.fail_after(60):
            return await _session(params)

    tools, triage, missing_is_error = anyio.run(run)
    assert sorted(tools) == EXPECTED_TOOLS
    assert triage["success"] is True and triage["severity"]["severity"] == "SEV1"
    assert missing_is_error is True


async def _session(params: Any) -> tuple[list[str], dict[str, Any], bool]:
    if SDK_MAJOR >= 2:
        from mcp import Client

        async with Client(params) as client:
            tools = [t.name for t in (await client.list_tools()).tools]
            result = await client.call_tool("triage_incident", {"incident": "Checkout down for all users in prod"})
            missing = await client.call_tool("classify_incident", {})
            return tools, result.structured_content, missing.is_error

    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = [t.name for t in (await session.list_tools()).tools]
        result = await session.call_tool("triage_incident", {"incident": "Checkout down for all users in prod"})
        missing = await session.call_tool("classify_incident", {})
        return tools, result.structuredContent, missing.isError


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "--transport" in capsys.readouterr().out
