"""Chat Request and Response Schemas."""

import time

from pydantic import BaseModel, Field

# ==========================================
# 1. Native Guardrail Chat Schemas
# ==========================================


class ChatRequest(BaseModel):
    """Native chat request from mock store or frontend."""

    message: str = Field(..., min_length=1, max_length=5000, description="User query message")
    customer_id: str = Field(default="cust_101", description="Authenticated customer ID")
    session_id: str | None = Field(default=None, description="Client session ID")


class SecurityEvaluation(BaseModel):
    """Guardrail evaluation summary."""

    input_passed: bool
    output_passed: bool
    pii_redacted: bool
    latency_ms: float
    threat_type: str | None = None
    rule_id: str | None = None


class ChatResponse(BaseModel):
    """Native chat response with security evaluation."""

    success: bool = True
    response: str
    security_evaluation: SecurityEvaluation


# ==========================================
# 2. OpenAI-Compatible Schemas (AnythingLLM)
# ==========================================


class OpenAIMessage(BaseModel):
    """OpenAI standard chat message."""

    role: str = Field(..., description="Role: system, user, assistant, or tool")
    content: str = Field(..., description="Message content")


class OpenAIChatRequest(BaseModel):
    """OpenAI standard chat completion request."""

    model: str = Field(default="qwen2.5:latest", description="Target model name")
    messages: list[OpenAIMessage] = Field(..., min_length=1, description="List of messages")
    temperature: float | None = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=512, ge=1)
    stream: bool | None = Field(default=False)


class OpenAIChoiceMessage(BaseModel):
    """Choice message in response."""

    role: str = "assistant"
    content: str


class OpenAIChoice(BaseModel):
    """Individual completion choice."""

    index: int = 0
    message: OpenAIChoiceMessage
    finish_reason: str = "stop"


class OpenAIUsage(BaseModel):
    """Token usage summary."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class OpenAIChatResponse(BaseModel):
    """OpenAI standard chat completion response."""

    id: str = Field(default_factory=lambda: f"chatcmpl-guardrail-{int(time.time() * 1000)}")
    object: str = "chat.completion"
    created: int = Field(default_factory=lambda: int(time.time()))
    model: str
    choices: list[OpenAIChoice]
    usage: OpenAIUsage = Field(default_factory=OpenAIUsage)
