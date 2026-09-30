"""Security Advanced Router: LLM-as-a-Judge and Adversarial Red Teaming Fuzzer Endpoints."""

from fastapi import APIRouter

from app.guardrails.judge_guardrail import judge_guardrail
from app.schemas.security import (
    AutoPatchRequest,
    AutoPatchResponse,
    FuzzRequest,
    FuzzSuiteResponse,
    FuzzTestCaseDTO,
    JudgePromptRequest,
    JudgeResponseRequest,
    JudgeResultResponse,
)
from app.security.adversarial_fuzzer import FuzzTestCase, adversarial_fuzzer

router = APIRouter(prefix="/security", tags=["Security Advanced (Judge & Fuzzer)"])


@router.post("/judge/prompt", response_model=JudgeResultResponse)
async def evaluate_prompt_with_judge(req: JudgePromptRequest) -> JudgeResultResponse:
    """Evaluate prompt with dual-layer LLM-as-a-Judge."""
    res = await judge_guardrail.evaluate_prompt(
        user_prompt=req.prompt,
        system_context=req.system_context,
        force_fast_mode=req.force_fast_mode,
    )
    return JudgeResultResponse(
        verdict=res.verdict,
        risk_score=res.risk_score,
        is_allowed=res.is_allowed,
        violation_category=res.violation_category,
        rationale=res.rationale,
        suggested_correction=res.suggested_correction,
        latency_ms=res.latency_ms,
        judge_mode=res.judge_mode,
    )


@router.post("/judge/response", response_model=JudgeResultResponse)
async def evaluate_response_with_judge(req: JudgeResponseRequest) -> JudgeResultResponse:
    """Evaluate candidate response for safety alignment, leakage, or hallucination."""
    res = await judge_guardrail.evaluate_response(
        user_prompt=req.prompt,
        candidate_response=req.candidate_response,
    )
    return JudgeResultResponse(
        verdict=res.verdict,
        risk_score=res.risk_score,
        is_allowed=res.is_allowed,
        violation_category=res.violation_category,
        rationale=res.rationale,
        suggested_correction=res.suggested_correction,
        latency_ms=res.latency_ms,
        judge_mode=res.judge_mode,
    )


@router.post("/fuzz/run", response_model=FuzzSuiteResponse)
async def run_adversarial_fuzzer(req: FuzzRequest) -> FuzzSuiteResponse:
    """Execute Garak/PyRIT style automated adversarial fuzzing suite."""
    fuzz_res = await adversarial_fuzzer.run_fuzzing_suite(
        categories=req.categories,
        samples_per_seed=req.samples_per_seed,
    )

    bypassed_dtos = [
        FuzzTestCaseDTO(
            id=tc.id,
            attack_category=tc.attack_category,
            mutation_strategy=tc.mutation_strategy,
            base_seed=tc.base_seed,
            mutated_prompt=tc.mutated_prompt,
            is_blocked=tc.is_blocked,
            threat_detected=tc.threat_detected,
            rule_matched=tc.rule_matched,
            latency_ms=tc.latency_ms,
        )
        for tc in fuzz_res.bypassed_cases
    ]

    return FuzzSuiteResponse(
        total_mutations=fuzz_res.total_mutations,
        blocked_count=fuzz_res.blocked_count,
        bypassed_count=fuzz_res.bypassed_count,
        defense_rate=fuzz_res.defense_rate,
        avg_latency_ms=fuzz_res.avg_latency_ms,
        category_summary=fuzz_res.category_summary,
        bypassed_cases=bypassed_dtos,
    )


@router.post("/fuzz/auto-patch", response_model=AutoPatchResponse)
async def auto_patch_fuzz_bypasses(req: AutoPatchRequest) -> AutoPatchResponse:
    """Synthesize and hot-reload protective rules for discovered bypasses."""
    cases = [
        FuzzTestCase(
            id=dto.id,
            attack_category=dto.attack_category,
            mutation_strategy=dto.mutation_strategy,
            base_seed=dto.base_seed,
            mutated_prompt=dto.mutated_prompt,
            is_blocked=dto.is_blocked,
            threat_detected=dto.threat_detected,
            rule_matched=dto.rule_matched,
            latency_ms=dto.latency_ms,
        )
        for dto in req.bypassed_cases
    ]

    patched_ids = await adversarial_fuzzer.auto_patch_vulnerabilities(cases)
    return AutoPatchResponse(
        success=True,
        synthesized_rules_count=len(patched_ids),
        patched_rule_ids=patched_ids,
    )
