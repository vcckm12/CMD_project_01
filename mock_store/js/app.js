/**
 * Guardrail Fashion Mock Store - Frontend Application Script
 */

function toggleChat() {
    const chatWidget = document.getElementById("chatWidget");
    chatWidget.classList.toggle("hidden");
}

function askAboutProduct(productName) {
    const chatWidget = document.getElementById("chatWidget");
    chatWidget.classList.remove("hidden");
    sendQuickMessage(`${productName} 가격과 배송 정보 알려줘`);
}

function sendQuickMessage(text) {
    const input = document.getElementById("chatInput");
    input.value = text;
    handleSendMessage();
}

async function handleSendMessage() {
    const input = document.getElementById("chatInput");
    const chatMessages = document.getElementById("chatMessages");
    const text = input.value.trim();

    if (!text) return;

    // Append user message bubble
    appendMessage(text, "user");
    input.value = "";
    input.disabled = true;

    // Show typing indicator
    const loadingId = appendLoadingIndicator();

    try {
        // Use relative URL so it works seamlessly behind Nginx reverse proxy
        const apiUrl = window.location.protocol.startsWith("http") 
            ? "/api/v1/chat/completions" 
            : "http://localhost:8000/api/v1/chat/completions";

        const response = await fetch(apiUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                message: text,
                customer_id: "cust_101",
            }),
        });

        removeLoadingIndicator(loadingId);

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            const errMsg = errData.message || "보안 검사 중 오류가 발생했습니다.";
            appendMessage(errMsg, "bot", true);
            return;
        }

        const data = await response.json();
        const isBlocked = !data.success || !data.security_evaluation?.input_passed;
        appendMessage(data.response, "bot", isBlocked, data.security_evaluation);

    } catch (err) {
        removeLoadingIndicator(loadingId);
        appendMessage("서버 연결에 실패했습니다. 백엔드 서비스 상태를 확인해 주세요.", "bot", true);
    } finally {
        input.disabled = false;
        input.focus();
    }
}

function appendMessage(text, sender, isBlocked = false, secEval = null) {
    const chatMessages = document.getElementById("chatMessages");
    const bubble = document.createElement("div");
    bubble.className = `msg-bubble ${sender} ${isBlocked ? "blocked" : ""}`;

    let secBadge = "";
    if (secEval && sender === "bot") {
        const piiBadge = secEval.pii_redacted ? " | <span style='color:#f59e0b;'>PII Redacted</span>" : "";
        secBadge = `<div style="font-size:0.75rem; color:#94a3b8; margin-top:6px; border-top:1px dashed #cbd5e1; padding-top:4px;">⏱️ Latency: ${secEval.latency_ms.toFixed(2)}ms${piiBadge}</div>`;
    }

    bubble.innerHTML = `<div class="msg-content">${escapeHtml(text)}</div>${secBadge}`;
    chatMessages.appendChild(bubble);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function appendLoadingIndicator() {
    const chatMessages = document.getElementById("chatMessages");
    const id = "loading-" + Date.now();
    const loadingBubble = document.createElement("div");
    loadingBubble.id = id;
    loadingBubble.className = "msg-bubble bot";
    loadingBubble.innerHTML = `<div class="msg-content"><i class="fa-solid fa-spinner fa-spin"></i> 가드레일 보안 검사 및 답변 생성 중...</div>`;
    chatMessages.appendChild(loadingBubble);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return id;
}

function removeLoadingIndicator(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}
