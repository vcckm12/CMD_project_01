"""Shop Tools API Router."""

from fastapi import APIRouter

from app.schemas.tools import ToolExecutionRequest, ToolExecutionResponse, ToolMetadata
from app.services.shop_service import shop_service

router = APIRouter(prefix="/tools", tags=["Shop Tools"])


@router.get("", response_model=list[ToolMetadata])
async def list_tools() -> list[ToolMetadata]:
    """Retrieve metadata of all available shop tools."""
    return shop_service.get_registered_tools()


@router.post("/execute", response_model=ToolExecutionResponse)
async def execute_tool(req: ToolExecutionRequest) -> ToolExecutionResponse:
    """Execute a specific shop tool with Execution Guardrail validation."""
    result = await shop_service.execute_tool(
        tool_name=req.tool_name,
        parameters=req.parameters,
        customer_id=req.customer_id,
    )
    return ToolExecutionResponse(
        tool_name=req.tool_name,
        status="success",
        data=result,
    )
