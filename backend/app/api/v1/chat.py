"""Native Guardrail Chat Router."""

from fastapi import APIRouter, BackgroundTasks, Request

from app.guardrails.input_guardrail import input_guardrail
from app.schemas.chat import ChatRequest, ChatResponse, SecurityEvaluation
from app.services.audit_service import audit_service
from app.services.slm_service import slm_service

router = APIRouter(prefix="/chat", tags=["Chat"])


@router.post("/completions", response_model=ChatResponse)
async def chat_completion(
    req: ChatRequest,
    request: Request,
    background_tasks: BackgroundTasks,
) -> ChatResponse:
    """Process shopping consultation query with multi-tier Input and Output guardrails."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    # 1. Input Guardrail Inspection (7 Steps)
    input_eval = input_guardrail.evaluate(req.message)

    if not input_eval.is_allowed:
        # Async Security Audit Logging
        background_tasks.add_task(
            audit_service.log_security_event,
            client_ip=client_ip,
            stage="INPUT_GUARDRAIL",
            threat_type=input_eval.threat_type or "SECURITY_VIOLATION",
            raw_payload=req.message,
            action_taken="BLOCKED",
            execution_time_ms=input_eval.latency_ms,
            rule_id=input_eval.rule_id,
        )

        return ChatResponse(
            success=False,
            response="🚨 [보안 정책 알림] 요청하신 내용에서 비정상적인 접근 또는 시스템 정책 위반 패턴이 감지되어 답변 생성이 차단되었습니다. 쇼핑몰 상품 및 배송 관련 질문을 남겨주시면 친절히 안내해 드리겠습니다.",
            security_evaluation=SecurityEvaluation(
                input_passed=False,
                output_passed=False,
                pii_redacted=False,
                latency_ms=input_eval.latency_ms,
                threat_type=input_eval.threat_type,
                rule_id=input_eval.rule_id,
            ),
        )

    # 2. SLM Service Inference & Output Guardrail (5 Steps)
    response_text, output_eval = await slm_service.generate_response(
        user_message=input_eval.sanitized_text,
        customer_id=req.customer_id,
    )

    # If Output Guardrail detected threats or redacted PII, record audit log
    if not output_eval.is_allowed or output_eval.pii_redacted:
        background_tasks.add_task(
            audit_service.log_security_event,
            client_ip=client_ip,
            stage="OUTPUT_GUARDRAIL",
            threat_type=",".join(output_eval.detected_threats)
            if output_eval.detected_threats
            else "PII_OR_LEAK",
            raw_payload=req.message,
            action_taken="REDACTED" if output_eval.is_allowed else "BLOCKED",
            execution_time_ms=output_eval.latency_ms,
            rule_id="OUT-POLICY",
        )

    total_latency = input_eval.latency_ms + output_eval.latency_ms

    return ChatResponse(
        success=output_eval.is_allowed,
        response=response_text,
        security_evaluation=SecurityEvaluation(
            input_passed=True,
            output_passed=output_eval.is_allowed,
            pii_redacted=output_eval.pii_redacted,
            latency_ms=total_latency,
            threat_type=",".join(output_eval.detected_threats)
            if output_eval.detected_threats
            else None,
            rule_id=None,
        ),
    )
