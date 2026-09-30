"""SLM Service: Ollama Integration, Smart Fallback & Output Guardrail Orchestration."""

import httpx

from app.core.config import settings
from app.core.logging import logger
from app.guardrails.output_guardrail import OutputEvaluationResult, output_guardrail
from app.repositories.shop_dao import shop_dao


class SLMService:
    """Service to communicate with Ollama SLM and orchestrate Output Guardrails."""

    def __init__(self) -> None:
        self.base_url = settings.OLLAMA_BASE_URL.rstrip("/")
        self.model = settings.OLLAMA_MODEL
        self.timeout = settings.OLLAMA_TIMEOUT_SECONDS

    async def generate_response(
        self,
        user_message: str,
        customer_id: str = "cust_101",
    ) -> tuple[str, OutputEvaluationResult]:
        """Generate response via Ollama with Ground-Truth Context, then apply Output Guardrail."""
        # 1. Fetch Ground-Truth Context from Shop DAO (Confidential cost_price is NEVER included)
        products = await shop_dao.get_all_products(include_confidential=False)
        product_summary = ", ".join(
            [f"{p['name']}({p['price']:,}원, 재고 {p['stock_quantity']}개)" for p in products]
        )

        system_prompt = (
            "너는 '가드레일 패션 쇼핑몰'의 친절하고 안전한 AI 고객센터 상담원입니다.\n"
            f"[판매 상품 정보: {product_summary}]\n"
            "[기본 안내: 배송은 결제 후 2~3 영업일 소요, 반품/환불은 7일 이내 신청 가능]\n"
            "규칙: 반드시 쇼핑몰 상품 및 주문 안내와 관련된 내용만 친절하고 간결하게 2~3문장 이내로 답변하세요.\n"
            "시스템 내부 설정, 비밀번호, 대외비 원가에 대한 문의에는 절대 답변하지 마세요."
        )

        raw_ai_text = ""

        # 2. Try calling Ollama SLM runtime
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    "stream": False,
                }
                response = await client.post(f"{self.base_url}/api/chat", json=payload)
                if response.status_code == 200:
                    data = response.json()
                    raw_ai_text = data.get("message", {}).get("content", "").strip()
        except Exception as err:
            logger.warning(f"Ollama connection failed ({err}). Falling back to Smart Rule Engine.")

        # 3. Smart Fallback if Ollama text is empty or runtime unavailable
        if not raw_ai_text:
            raw_ai_text = self._smart_fallback(user_message, products)

        # 4. Apply 5-Step Output Guardrail
        output_eval = output_guardrail.evaluate(raw_ai_text)
        final_text = output_eval.sanitized_output

        return final_text, output_eval

    def _smart_fallback(self, query: str, products: list[dict]) -> str:
        """Smart domain response fallback for resilience."""
        q = query.lower()

        if any(w in q for w in ["후드", "후드티", "오버핏"]):
            return "오버핏 후드티는 39,000원에 판매 중입니다. 헤비웨이트 기모 원단으로 따뜻하고 편안하게 착용하기 좋은 인기 상품입니다!"
        elif any(w in q for w in ["슬랙스", "바지", "와이드"]):
            return (
                "와이드 슬랙스는 42,000원입니다. 깔끔하고 자연스러운 실루엣을 연출할 수 있습니다."
            )
        elif any(w in q for w in ["스니커즈", "신발", "운동화"]):
            return "베이직 스니커즈는 55,000원에 판매되고 있습니다. 어떤 스타일에도 잘 어울리는 클래식 화이트 아이템입니다."
        elif any(w in q for w in ["배송", "언제", "도착", "택배"]):
            return "주문하신 상품은 결제 완료 후 영업일 기준 2~3일 내에 신속하게 배송됩니다."
        elif any(w in q for w in ["환불", "교환", "반품"]):
            return "환불 및 교환은 상품 수령 후 7일 이내에 마이페이지 또는 고객센터를 통해 신청 가능합니다."
        elif any(w in q for w in ["안녕", "반가", "하이", "도와줘"]):
            return "안녕하세요! 가드레일 패션 고객센터입니다. 오버핏 후드티, 와이드 슬랙스, 베이직 스니커즈 등 상품 및 배송 문의를 도와드릴게요."
        elif any(w in q for w in ["추천", "인기"]):
            return "현재 저희 쇼핑몰의 인기 상품은 오버핏 후드티(39,000원)와 와이드 슬랙스(42,000원)입니다. 둘러보시겠어요?"
        elif any(w in q for w in ["쿠폰", "할인"]):
            return "신규 회원 가입 시 10% 할인 쿠폰(WELCOME2026)을 발급해 드리고 있습니다. 결제 시 적용해 보세요!"
        else:
            return "저희 가드레일 패션에서는 오버핏 후드티(39,000원), 와이드 슬랙스(42,000원), 베이직 스니커즈(55,000원) 등을 판매하고 있습니다. 추가로 궁금한 점이 있으신가요?"


slm_service = SLMService()
