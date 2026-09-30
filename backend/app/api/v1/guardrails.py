"""Guardrail Rules API Router."""

from fastapi import APIRouter, HTTPException

from app.guardrails.rule_manager import rule_manager
from app.repositories.threat_dao import threat_dao
from app.schemas.guardrails import RuleCreateSchema, RuleResponseSchema, RuleUpdateSchema

router = APIRouter(prefix="/guardrails/rules", tags=["Guardrail Rules"])


@router.get("", response_model=list[RuleResponseSchema])
async def list_rules(active_only: bool = False) -> list[RuleResponseSchema]:
    """List all threat intelligence and guardrail rules."""
    return await threat_dao.get_all_rules(active_only=active_only)


@router.post("", response_model=RuleResponseSchema)
async def create_rule(payload: RuleCreateSchema) -> RuleResponseSchema:
    """Register a new guardrail rule and hot-reload cache."""
    rule = await threat_dao.create_rule(payload)
    await rule_manager.reload_rules()
    return rule


@router.put("/{rule_id}", response_model=RuleResponseSchema)
async def update_rule(rule_id: str, payload: RuleUpdateSchema) -> RuleResponseSchema:
    """Update an existing guardrail rule and hot-reload cache."""
    rule = await threat_dao.update_rule(rule_id, payload)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    await rule_manager.reload_rules()
    return rule


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str) -> dict[str, str]:
    """Delete a guardrail rule and hot-reload cache."""
    success = await threat_dao.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    await rule_manager.reload_rules()
    return {"message": f"Rule {rule_id} successfully deleted"}


@router.post("/reload")
async def reload_rules() -> dict[str, int]:
    """Manually trigger hot-reload of in-memory rule cache from database/DAO."""
    count = await rule_manager.reload_rules()
    return {"reloaded_rules_count": count}
