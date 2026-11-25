"""MCP server that exposes the IncidentResolution tools.

Tools are discovered from the methods of ``IncidentResolution``: every public method whose
docstring lists ``mcp`` under ``expose`` becomes an MCP tool. The docstring's ``description``
becomes the tool description, each ``args`` description becomes the parameter description in
the input schema, and ``tags`` are sent in the tool's ``_meta``. Adding a new tool to
``incident.py`` is enough to publish it here.

All tools only read their inputs and the local knowledge files, so every tool is marked
read-only, idempotent and closed-world.

Run it:
    python -m incident_mcp.server                                  # stdio (Claude Code / Desktop)
    python -m incident_mcp.server --transport streamable-http --port 8000
    incident-mcp --help                                            # after `pip install -e .`

Works with the MCP Python SDK 2.x (``MCPServer``) and 1.x (``FastMCP``).
"""

from __future__ import annotations

import argparse
import inspect
import sys
from pathlib import Path
from typing import Annotated, Any, Callable

import yaml
from loguru import logger
from pydantic import Field

from mcp.types import ToolAnnotations

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as _ServerClass

    SDK_MAJOR = 2
except ImportError:  # MCP Python SDK 1.x
    from mcp.server.fastmcp import FastMCP as _ServerClass  # type: ignore[no-redef]

    SDK_MAJOR = 1

from incident_mcp.incident import IncidentResolution

SERVER_NAME = "incident-resolution"

INSTRUCTIONS = """\
Tools for IT incident response. They analyse the text you give them and local knowledge files;
they never change a real system.

Suggested flow for a new incident:
1. classify_incident and assess_severity (or triage_incident for everything in one call).
2. If logs are provided, analyze_logs. If recent changes are known, correlate_with_changes.
3. find_root_cause and find_similar_incidents.
4. generate_remediation and get_runbook. After a fix, verify_recovery.
5. determine_escalation. If escalation is needed, create_escalation_summary.
   For management, create_executive_summary. After resolution, draft_postmortem.

Always show the evidence for a root cause and call it a hypothesis until the user confirms it.
Never say a fix has been applied: the tools only recommend. Steps marked requires_approval
need human approval before they are carried out in production.
"""

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


# --------------------------------------------------------------------------------------
# Tool discovery
# --------------------------------------------------------------------------------------


def parse_tool_doc(fn: Callable[..., Any]) -> dict[str, Any] | None:
    """Return the parsed docstring definition of a tool, or None if it is not exposed via MCP."""
    doc = inspect.getdoc(fn)
    if not doc:
        return None
    try:
        spec = yaml.safe_load(doc)
    except yaml.YAMLError as e:
        logger.warning(f"Skipping {fn.__name__}: docstring is not valid YAML ({e})")
        return None
    if not isinstance(spec, dict) or "mcp" not in (spec.get("expose") or []):
        return None
    if not isinstance(spec.get("description"), str) or not spec["description"].strip():
        logger.warning(f"Skipping {fn.__name__}: docstring has no description")
        return None
    return spec


def build_handler(method: Callable[..., Any], name: str, spec: dict[str, Any]) -> Callable[..., Any]:
    """Wrap a bound tool method in a plain function whose signature carries the arg descriptions.

    The MCP SDK builds the tool's JSON input schema from the function signature, so each
    parameter is annotated with ``Annotated[type, Field(description=...)]`` taken from the
    docstring ``args`` section. Defaults and required/optional status come from the method.
    """
    signature = inspect.signature(method, eval_str=True)  # bound method: no `self`
    arg_docs = spec.get("args") or {}
    parameters = []
    for param in signature.parameters.values():
        annotation = param.annotation if param.annotation is not inspect.Parameter.empty else Any
        description = (arg_docs.get(param.name) or {}).get("description")
        if description:
            annotation = Annotated[annotation, Field(description=str(description).strip())]
        parameters.append(param.replace(annotation=annotation))

    def handler(**kwargs: Any) -> dict[str, Any]:
        return method(**kwargs)

    handler.__name__ = name
    handler.__qualname__ = name
    handler.__doc__ = spec["description"].strip()
    handler.__signature__ = signature.replace(parameters=parameters, return_annotation=dict[str, Any])  # type: ignore[attr-defined]
    return handler


def discover_tools(service: IncidentResolution) -> list[tuple[str, dict[str, Any], Callable[..., Any]]]:
    """Find (name, spec, handler) for every MCP-exposed tool on the service."""
    tools = []
    for name, fn in inspect.getmembers(type(service), inspect.isfunction):
        if name.startswith("_"):
            continue
        spec = parse_tool_doc(fn)
        if spec is None:
            continue
        tools.append((name, spec, build_handler(getattr(service, name), name, spec)))
    return tools


# --------------------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------------------


def create_server(
    knowledge_dir: str | Path | None = None,
    templates_dir: str | Path | None = None,
    service: IncidentResolution | None = None,
) -> Any:
    """Create the MCP server with every exposed IncidentResolution tool and the workflow prompt."""
    service = service or IncidentResolution(knowledge_dir=knowledge_dir, templates_dir=templates_dir)
    server = _ServerClass(SERVER_NAME, instructions=INSTRUCTIONS)

    add_tool_params = inspect.signature(server.add_tool).parameters
    for name, spec, handler in discover_tools(service):
        kwargs: dict[str, Any] = {"name": name, "description": handler.__doc__}
        if "title" in add_tool_params:
            kwargs["title"] = name.replace("_", " ").capitalize()
        if "annotations" in add_tool_params:
            kwargs["annotations"] = READ_ONLY
        if "meta" in add_tool_params and spec.get("tags"):
            kwargs["meta"] = {"tags": list(spec["tags"])}
        server.add_tool(handler, **kwargs)
        logger.debug(f"Registered tool {name}")

    @server.prompt(
        name="incident_response",
        description="Step-by-step workflow to triage, diagnose, remediate and escalate an incident with these tools.",
    )
    def incident_response(incident: str, log_text: str = "", audience: str = "engineering") -> str:
        logs = f"\n\nLogs provided by the user:\n```\n{log_text}\n```" if log_text.strip() else ""
        summary_tool = "create_executive_summary" if audience.strip().lower() in ("management", "executive") else (
            "create_escalation_summary"
        )
        return (
            f"{INSTRUCTIONS}\n"
            f"Handle this incident now. Finish with a summary for the {audience} audience using {summary_tool}.\n\n"
            f"Incident:\n{incident}{logs}"
        )

    logger.info(f"MCP server '{SERVER_NAME}' ready (MCP SDK {SDK_MAJOR}.x)")
    return server


def run_server(server: Any, transport: str = "stdio", host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the server on the chosen transport."""
    if transport == "stdio":
        server.run("stdio")
    elif SDK_MAJOR >= 2:
        server.run(transport, host=host, port=port)
    else:
        server.settings.host = host
        server.settings.port = port
        server.run(transport)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="incident-mcp", description="MCP server for the IncidentResolution tools")
    parser.add_argument("--transport", choices=["stdio", "streamable-http", "sse"], default="stdio",
                        help="stdio for local clients (default), streamable-http for a shared server")
    parser.add_argument("--host", default="127.0.0.1", help="host for HTTP transports (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="port for HTTP transports (default 8000)")
    parser.add_argument("--knowledge-dir", help="folder with your own knowledge YAML files")
    parser.add_argument("--templates-dir", help="folder with your own summary templates")
    parser.add_argument("--log-level", default="INFO", help="loguru log level (default INFO)")
    args = parser.parse_args(argv)

    # Logs must go to stderr: with the stdio transport, stdout carries the MCP protocol.
    logger.remove()
    logger.add(sys.stderr, level=args.log_level.upper())

    server = create_server(knowledge_dir=args.knowledge_dir, templates_dir=args.templates_dir)
    run_server(server, args.transport, args.host, args.port)


if __name__ == "__main__":
    main()
