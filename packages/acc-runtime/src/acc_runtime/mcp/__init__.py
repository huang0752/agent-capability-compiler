"""MCP transport adapters."""

from acc_runtime.mcp.schema_projection import (
    McpSchemaProjectionError,
    project_mcp_output_schema,
)
from acc_runtime.mcp.server import (
    CapabilityMcpServer,
    ContextualMcpRuntime,
    McpRuntime,
    PrincipalCapabilityMcpServer,
    PrincipalResolver,
)

__all__ = [
    "CapabilityMcpServer",
    "ContextualMcpRuntime",
    "McpRuntime",
    "McpSchemaProjectionError",
    "PrincipalCapabilityMcpServer",
    "PrincipalResolver",
    "project_mcp_output_schema",
]
