"""OpenAI Compatible Chat Completion Router (for AnythingLLM Integration)."""

from fastapi import APIRouter, BackgroundTasks, Request

from app.guardrails.input_guardrail import input_guardrail
from app.schemas.chat import (
    OpenAIChatRequest,
    OpenAIChatResponse,
    OpenAIChoice,
    OpenAIChoiceMessage,
    OpenAIUsage,
)
from app.services.audit_service import audit_service
from app.services.slm_service import slm_service

router = APIRouter(tags=["OpenAI Compatibility"])


@router.post("/v1/chat/completions", response_model=OpenAIChatResponse)
async def openai_chat_completions(
    req: OpenAIChatRequest,
    request: Request,
    background_tasks: BackgroundTasks,
) -> OpenAIChatResponse:
    """OpenAI standard endpoint for AnythingLLM Desktop and external clients."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Extract latest user message
    user_content = ""
    for msg in reversed(req.messages):
        if msg.role.lower() == "user":
            user_content = msg.content
            break

    # 1. Input Guardrail
    input_eval = input_guardrail.evaluate(user_content)

    if not input_eval.is_allowed:
        background_tasks.add_task(
            audit_service.log_security_event,
            client_ip=client_ip,
            stage="INPUT_GUARDRAIL",
            threat_type=input_eval.threat_type or "SECURITY_VIOLATION",
            raw_payload=user_content,
            action_taken="BLOCKED",
            execution_time_ms=input_eval.latency_ms,
            rule_id=input_eval.rule_id,
        )

        return OpenAIChatResponse(
            model=req.model,
            choices=[
                OpenAIChoice(
                    index=0,
                    message=OpenAIChoiceMessage(
                        role="assistant",
                        content="🚨 [보안 정책 알림] 요청하신 내용에서 비정상적인 접근 또는 시스템 정책 위반 패턴이 감지되어 답변 생성이 차단되었습니다.",
                    ),
                    finish_reason="security_block",
                )
            ],
            usage=OpenAIUsage(
                prompt_tokens=len(user_content),
                completion_tokens=10,
                total_tokens=len(user_content) + 10,
            ),
        )

    # 2. SLM Inference & Output Guardrail
    response_text, output_eval = await slm_service.generate_response(
        user_message=input_eval.sanitized_text,
    )

    if not output_eval.is_allowed or output_eval.pii_redacted:
        background_tasks.add_task(
            audit_service.log_security_event,
            client_ip=client_ip,
            stage="OUTPUT_GUARDRAIL",
            threat_type=",".join(output_eval.detected_threats)
            if output_eval.detected_threats
            else "PII_OR_LEAK",
            raw_payload=user_content,
            action_taken="REDACTED" if output_eval.is_allowed else "BLOCKED",
            execution_time_ms=output_eval.latency_ms,
            rule_id="OUT-POLICY",
        )

    return OpenAIChatResponse(
        model=req.model,
        choices=[
            OpenAIChoice(
                index=0,
                message=OpenAIChoiceMessage(
                    role="assistant",
                    content=response_text,
                ),
                finish_reason="stop",
            )
        ],
        usage=OpenAIUsage(
            prompt_tokens=len(user_content),
            completion_tokens=len(response_text),
            total_tokens=len(user_content) + len(response_text),
        ),
    )
