// DOM helpers. Dynamic values only ever become text nodes or attributes: no innerHTML anywhere,
// so a model answer or product name can never turn into markup (DES-004 §1.1, DES-006 §4.2).

export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === "text") el.textContent = value;
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function mount(target, ...children) {
  target.replaceChildren(...children.flat().filter(Boolean));
}

export const krw = (n) => `${Number(n).toLocaleString("ko-KR")}원`;

export function kst(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString("ko-KR", { timeZone: "Asia/Seoul", hour12: false });
}

// Minimal safe renderer for assistant text: paragraphs, "- " / "1. " lists and **bold**, all as text.
export function renderAnswer(text) {
  const root = h("div", { class: "answer" });
  let list = null;
  for (const raw of String(text).split("\n")) {
    const line = raw.trimEnd();
    const item = line.match(/^\s*(?:[-*]|\d+\.)\s+(.*)$/);
    if (item) {
      if (!list) {
        list = h(/^\s*\d+\./.test(line) ? "ol" : "ul");
        root.append(list);
      }
      list.append(h("li", {}, ...inline(item[1])));
      continue;
    }
    list = null;
    if (line.trim()) root.append(h("p", {}, ...inline(line)));
  }
  return root;
}

function inline(text) {
  return text.split(/(\*\*[^*]+\*\*)/g).filter(Boolean).map((part) =>
    part.startsWith("**") && part.endsWith("**") ? h("strong", { text: part.slice(2, -2) }) : document.createTextNode(part)
  );
}

export function uuidv4() {
  return crypto.randomUUID();
}
