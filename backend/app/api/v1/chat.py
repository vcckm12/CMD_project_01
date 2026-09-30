"""쇼핑몰 AI 상담 및 대화형 챗봇 API 라우터 모듈 (/api/v1/chat).

[엔드포인트 처리 흐름 및 보안 아키텍처]
1. 클라이언트(사용자/UI)가 고객 ID(`customer_id`)와 상담 메시지(`message`)를 POST `/api/v1/chat/completions`로 전송
2. [1차 관문 - 입력 가드레일 (Input Guardrail)]
   - 유니코드 정규화, 제로 너비 공백 제거, 동형이의어 복원, 정규식 규칙 및 TF-IDF 의미론적 유사도 검사 수행
   - 공격 탐지 시: `BackgroundTasks`로 비동기 감사 로그를 기록하고, AI 모델을 호출하지 않고 즉시 400/차단 응답 반환
3. [2차 관문 - AI 추론 및 실행 가드레일 (SLM & Execution Guardrail)]
   - 안전한 입력 텍스트만 SLM에 전달되고, 주문 조회/취소 등 함수 호출 시 본인 소유권(BOLA)을 검증
4. [3차 관문 - 출력 가드레일 (Output Guardrail)]
   - 생성된 답변에서 개인정보(전화번호, 카드번호 등) 마스킹, 대외비 원가 마스킹, 역방향 셸 차단, XSS 이스케이프 처리
5. 최종적으로 안전성이 검증된 답변과 보안 평가 메트릭(SecurityEvaluation)을 함께 반환
"""

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
    """쇼핑몰 AI 고객 상담 질의를 다계층 가드레일(입력/실행/출력)로 안전하게 처리합니다."""
    # 클라이언트의 실제 접속 IP 추출 (감사 로그용)
    client_ip = request.client.host if request.client else "127.0.0.1"

    # [1단계] 7단계 심층 입력 가드레일 검사 수행
    input_eval = input_guardrail.evaluate(req.message)

    # 공격(Prompt Injection, Jailbreak 등)이 감지되어 차단된 경우
    if not input_eval.is_allowed:
        # 백그라운드 태스크(BackgroundTasks)를 활용하여 사용자 응답 지연 없이 비동기로 감사 로그 기록
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

        # AI 모델 호출 비용을 아끼고 즉시 안전 차단 안내문 반환
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

    # [2단계] 입력 검사를 통과한 정제된 텍스트(sanitized_text)로 SLM 모델 추론 및 도구 실행 수행
    response_text, output_eval = await slm_service.generate_response(
        user_message=input_eval.sanitized_text,
        customer_id=req.customer_id,
    )

    # [3단계] 출력 가드레일 결과에 따른 감사 로깅
    # 출력 검사에서 위험 요소가 차단되었거나 개인정보가 비식별화(마스킹)된 경우 보안 이벤트 기록
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

    # 총 소요 시간(입력 검사 + 출력 검사) 계산
    total_latency = input_eval.latency_ms + output_eval.latency_ms

    # 최종 결과 반환
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

