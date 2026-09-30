"""고급 보안 API 라우터 모듈 (/api/v1/security).

[주요 기능 및 엔드포인트 목록]
1. POST `/api/v1/security/judge/prompt`: 듀얼 레이어 LLM-as-a-Judge를 통해 사용자 프롬프트의 간접 주입 및 기만 탈옥 여부 정밀 평가
2. POST `/api/v1/security/judge/response`: 모델 생성 답변의 대외비 유출 및 안전성을 사후 검증하고 자가 교정 문구 생성
3. POST `/api/v1/security/fuzz/run`: Garak / PyRIT 아키텍처 기반의 자동화 적대적 퍼징(Red Teaming) 공격 스위트 실행
4. POST `/api/v1/security/fuzz/auto-patch`: 퍼징 테스트에서 발견된 우회 공격에 대해 방어 규칙을 자동 합성하고 무중단 적용(Hot-Reload)
"""

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
    """듀얼 레이어 LLM-as-a-Judge 심사관을 통해 프롬프트의 지능형 공격 여부를 심사합니다."""
    # 1단계 휴리스틱 + 2단계 SLM 심층 심사 수행
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
    """AI 모델이 생성한 후보 답변의 안전성을 사후 검증하고 필요 시 자가 교정(Self-Correction) 문구를 제안합니다."""
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
    """Garak / PyRIT 스타일의 자동화 적대적 퍼징(Red Teaming) 공격 테스트를 실행합니다."""
    # 지정된 공격 카테고리와 샘플 수에 따라 변이 공격을 생성하고 가드레일 방어율을 측정
    fuzz_res = await adversarial_fuzzer.run_fuzzing_suite(
        categories=req.categories,
        samples_per_seed=req.samples_per_seed,
    )

    # 방어벽을 뚫고 통과(Bypass)한 취약점 케이스들을 DTO 형태로 변환
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
    """퍼징 중 발견된 우회 취약점 케이스에 대해 새로운 방어 규칙을 자동 합성하고 무중단 핫 리로드합니다."""
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

    # 취약점 패턴 분석 -> 새 규칙 자동 등록 -> 인메모리 캐시 갱신
    patched_ids = await adversarial_fuzzer.auto_patch_vulnerabilities(cases)
    return AutoPatchResponse(
        success=True,
        synthesized_rules_count=len(patched_ids),
        patched_rule_ids=patched_ids,
    )

