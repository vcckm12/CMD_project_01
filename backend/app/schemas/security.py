"""Security DTO Schemas for LLM-as-a-Judge and Adversarial Fuzzer."""

from pydantic import BaseModel, Field


class JudgePromptRequest(BaseModel):
    """Request to evaluate user prompt with LLM-as-a-Judge."""

    prompt: str = Field(..., min_length=1, max_length=5000, description="Prompt to evaluate")
    system_context: str = Field(default="", description="Optional system context")
    force_fast_mode: bool = Field(default=False, description="Whether to enforce sub-millisecond heuristic mode")


class JudgeResponseRequest(BaseModel):
    """Request to evaluate candidate response with LLM-as-a-Judge."""

    prompt: str = Field(..., min_length=1, max_length=5000)
    candidate_response: str = Field(..., min_length=1, max_length=5000)


class JudgeResultResponse(BaseModel):
    """Result of Judge evaluation."""

    verdict: str
    risk_score: float
    is_allowed: bool
    violation_category: str
    rationale: str
    suggested_correction: str | None = None
    latency_ms: float
    judge_mode: str


class FuzzRequest(BaseModel):
    """Request to trigger automated adversarial red teaming fuzzing."""

    categories: list[str] | None = Field(
        default=None,
        description="Target attack categories (PROMPT_INJECTION, JAILBREAK_ROLEPLAY, INDIRECT_INJECTION, CIPHER_OBFUSCATION, COMMERCIAL_COST_THEFT)",
    )
    samples_per_seed: int = Field(default=2, ge=1, le=5, description="Number of mutations per seed")


class FuzzTestCaseDTO(BaseModel):
    """DTO for individual fuzz test case."""

    id: str
    attack_category: str
    mutation_strategy: str
    base_seed: str
    mutated_prompt: str
    is_blocked: bool
    threat_detected: str | None = None
    rule_matched: str | None = None
    latency_ms: float


class FuzzSuiteResponse(BaseModel):
    """Response of adversarial fuzzing execution."""

    total_mutations: int
    blocked_count: int
    bypassed_count: int
    defense_rate: float
    avg_latency_ms: float
    category_summary: dict[str, dict[str, int]]
    bypassed_cases: list[FuzzTestCaseDTO]


class AutoPatchRequest(BaseModel):
    """Request to auto-synthesize protective rules for bypassed fuzz cases."""

    bypassed_cases: list[FuzzTestCaseDTO]


class AutoPatchResponse(BaseModel):
    """Response of auto-patch synthesis."""

    success: bool
    synthesized_rules_count: int
    patched_rule_ids: list[str]
