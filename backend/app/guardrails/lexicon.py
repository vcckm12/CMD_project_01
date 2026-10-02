"""Context-rule vocabularies (DES-006 §3.2). A context rule needs several of these to co-occur;
no single word decides intent. All are case-insensitive and use bounded repeats only."""

from __future__ import annotations

import regex

FLAGS = regex.IGNORECASE | regex.V0


def _c(pattern: str) -> regex.Pattern:
    return regex.compile(pattern, FLAGS)


EXEC_REQUEST = _c(r"실행|수행|작동|돌려|run\b|execute|exec\b")
OUTPUT_REQUEST = _c(
    r"출력|공개|알려|보여|말해|불러|읊어|적어|print|reveal|show|tell\s{1,5}me|display|output|dump|list\s{1,5}(?:all|every)"
)
PERFORM_REQUEST = _c(
    r"작성|묘사|만들어|생성|써\s{0,3}줘|써\s{0,3}봐|write|describe|create|generate|compose|include|포함"
)
SECRET_TARGET = _c(
    r"(?:관리자|마스터|어드민|루트|admin|master|root)\s{0,3}(?:키|key|암호|비밀번호|패스워드|password|토큰|token)"
    r"|(?:DB|디비|데이터베이스|database)\s{0,3}(?:암호|비밀번호|패스워드|password|접속\s{0,3}정보|credential)"
    r"|시스템\s{0,3}프롬프트|system\s{0,3}prompt|(?:hidden|initial|original|secret)\s{1,3}(?:instructions|prompt)"
    r"|(?:전체|모든|전\s{0,2})\s{0,3}(?:고객|회원|사용자)\s{0,3}(?:개인\s{0,2}정보|정보|목록|명단)"
    r"|api\s{0,3}key|secret\s{0,3}key|비밀\s{0,3}키|인증\s{0,3}키|환경\s{0,3}변수|env(?:ironment)?\s{0,3}var"
)
ROLEPLAY = _c(
    r"역할극|롤플레이|소설|대본|각본|시나리오|가상(?:의|으로)?|상상|영화|연극|persona|role\s{0,2}-?\s{0,2}play"
    r"|pretend|imagine|fiction|screenplay|you\s{1,5}are\s{1,5}now|너는\s{0,3}이제|지금부터\s{0,3}너는"
)
RULE_INVALIDATION = _c(
    r"(?:규칙|지침|제한|필터|검열|정책|rules?|instructions|guidelines|restrictions|filters?)"
    r"\s{0,3}(?:은|는|을|를|이|가)?\s{0,3}(?:무시|없|해제|벗어|잊|무효|ignore|bypass|disable|no\s{1,3}longer)"
    r"|without\s{1,3}(?:any\s{1,3})?(?:rules|restrictions|filters|censorship)|제한\s{0,3}없이|검열\s{0,3}없이"
)
GRANDMA = _c(r"할머니|할아버지|자장가|grandma|grandmother|grandpa|lullaby|bedtime\s{1,3}story")
EXTERNAL_IMAGE_OR_URL = _c(
    r"!\[|마크다운\s{0,3}이미지|markdown\s{0,3}image|이미지\s{0,3}(?:태그|링크|url|주소)|image\s{0,3}(?:tag|link|url)"
    r"|https?://|\burl\b|링크|웹훅|webhook|외부\s{0,3}(?:서버|주소)"
)
VALUE_BINDING = _c(
    r"\?[\w-]{1,20}=|=\s{0,2}\[[^\]\n]{1,40}\]|=\s{0,2}\{[^}\n]{1,40}\}|첨부|붙여|넣어|포함|바인딩|append|attach|include|embed"
    r"|파라미터|parameter|query"
)
PLACEHOLDER = _c(r"=\s{0,2}\[[^\]\n]{1,40}\]|=\s{0,2}\{[^}\n]{1,40}\}")
PY_INTROSPECTION = _c(r"__subclasses__|__mro__|__globals__|__builtins__|metaclass")
PY_SINK = _c(r"popen|\bexec\b|\beval\b|os\.system|subprocess")
SQL_DESTRUCTIVE = _c(r"drop\s{1,10}table|delete\s{1,10}from|truncate\s{1,10}table")
SHELL_DESTRUCTIVE = _c(r"rm\s{1,10}-[a-z]{1,6}\s{1,10}/|curl.{0,120}\x7c\s{0,10}(?:sh|bash)")
FOLLOWUP_REFERENCE = _c(
    r"그\s{0,2}값|그\s{0,2}변수|그\s{0,2}키|실제\s{0,2}값|방금\s{0,3}말한|아까\s{0,3}(?:그|말한)|들어\s{0,2}(?:가\s{0,2})?있는\s{0,2}값"
    r"|that\s{1,3}(?:value|key|variable)|the\s{1,3}(?:actual|real)\s{1,3}value|its\s{1,3}value"
)
# Untrusted tool/RAG content that tries to act as instructions (RULE_INDIRECT_CONTEXT_INJECTION).
EMBEDDED_INSTRUCTION = _c(
    r"(?:ignore|disregard|forget)\s{0,20}(?:all\s{1,10})?(?:previous|prior|above|system)\s{0,20}(?:instructions|rules|prompt)"
    r"|(?:이전|기존|위의?|시스템).{0,30}(?:지침|명령|규칙|지시).{0,30}(?:무시|폐기|잊어)"
    r"|you\s{1,5}are\s{1,5}now|new\s{1,3}instructions?\s{0,3}:|(?m:^)\s{0,5}(?:system|assistant)\s{0,3}:"
    r"|(?:이제부터|지금부터)\s{0,3}(?:너는|당신은)|(?:AI|어시스턴트|assistant)(?:는|에게)?\s{0,5}(?:다음|아래)\s{0,3}(?:지시|명령)"
)

WINDOW_CHARS = 500

# Words whose *appearance only after de-obfuscation* signals deliberate evasion
# (RULE_OBFUSCATED_SENSITIVE_TERM). Leet is excluded: "P@ssw0rd" examples are common and benign.
SENSITIVE_TERMS = _c(
    r"system\s{0,2}prompt|시스템\s{0,2}프롬프트|프롬프트|jail\s{0,2}break|탈옥|dan\s{0,2}mode|비밀\s{0,2}번호|패스\s{0,2}워드"
    r"|pass\s{0,2}word|passwd|관리자\s{0,2}(?:권한|키|비밀번호)|\badmin|ignore|무시|지침|instructions?|secret|credential"
    r"|api\s{0,2}key|token|\broot\b|union\s{0,2}select|drop\s{0,2}table|rm\s{0,2}-rf|\bshell|guardrail|가드레일"
    r"|developer\s{0,2}mode|개발자\s{0,2}모드|prompt"
)
