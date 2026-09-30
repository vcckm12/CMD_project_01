"""Shop Tools Request and Response Schemas."""

from typing import Any

from pydantic import BaseModel, Field


class ToolMetadata(BaseModel):
    """Metadata describing an executable tool."""

    name: str
    description: str
    parameters: dict[str, Any]
    required_permissions: list[str] = Field(default_factory=list)


class ToolExecutionRequest(BaseModel):
    """Tool invocation payload."""

    tool_name: str = Field(..., description="Target tool identifier")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Tool execution arguments")
    customer_id: str = Field(default="cust_101", description="Current customer context")


class ToolExecutionResponse(BaseModel):
    """Tool execution result payload."""

    tool_name: str
    status: str = "success"  # "success" or "failed"
    data: Any = None
    error: str | None = None
