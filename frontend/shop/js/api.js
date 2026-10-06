// API client (DES-005 §1.1). The access token lives only in memory; the refresh token is an
// HttpOnly cookie and the CSRF value is read from its cookie for the double-submit header.

let accessToken = null;
let currentUser = null;
let refreshing = null;

export const session = {
  get user() {
    return currentUser;
  },
  get signedIn() {
    return accessToken !== null;
  },
};

function csrfCookie() {
  const match = document.cookie.match(/(?:^|;\s*)guardrail_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

export class ApiError extends Error {
  constructor(status, body, headers) {
    const err = (body && body.error) || {};
    super(err.message || "요청을 처리하지 못했습니다.");
    this.status = status;
    this.code = err.code || "UNKNOWN";
    this.reason = err.reason || null;
    this.requestId = headers.get("x-request-id");
    this.retryAfter = headers.get("retry-after");
    this.body = body;
  }
}

async function send(method, path, { body, headers = {}, auth = true } = {}) {
  const init = { method, headers: { Accept: "application/json", ...headers }, credentials: "same-origin" };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  if (auth && accessToken) init.headers.Authorization = `Bearer ${accessToken}`;
  const response = await fetch(path, init);
  let payload = null;
  if (response.status !== 204) {
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
  }
  return { response, payload };
}

export async function request(method, path, options = {}) {
  let { response, payload } = await send(method, path, options);
  if (response.status === 401 && options.auth !== false && payload?.error?.code === "TOKEN_EXPIRED") {
    if (await refresh()) ({ response, payload } = await send(method, path, options));
  }
  if (!response.ok && !(response.status === 403 && payload?.status === "blocked")) {
    throw new ApiError(response.status, payload, response.headers);
  }
  return { status: response.status, data: payload, headers: response.headers };
}

export async function refresh() {
  if (!csrfCookie()) return false; // no session cookie: nothing to refresh, skip a pointless 403
  if (!refreshing) {
    refreshing = (async () => {
      const { response, payload } = await send("POST", "/api/v1/auth/refresh", {
        auth: false,
        headers: { "X-CSRF-Token": csrfCookie() },
      });
      if (!response.ok) {
        accessToken = null;
        currentUser = null;
        return false;
      }
      accessToken = payload.data.access_token;
      currentUser = payload.data.user;
      return true;
    })().finally(() => {
      refreshing = null;
    });
  }
  return refreshing;
}

export async function login(email, password) {
  const { data } = await request("POST", "/api/v1/auth/login", { body: { email, password }, auth: false });
  accessToken = data.data.access_token;
  currentUser = data.data.user;
}

export async function register(email, password) {
  await request("POST", "/api/v1/auth/register", { body: { email, password }, auth: false });
}

export async function logout() {
  try {
    await request("POST", "/api/v1/auth/logout", { headers: { "X-CSRF-Token": csrfCookie() } });
  } finally {
    accessToken = null;
    currentUser = null;
  }
}

export const get = (path) => request("GET", path).then((r) => r.data);
export const post = (path, body, headers) => request("POST", path, { body, headers });
export const del = (path) => request("DELETE", path);

// Chat with stage events (DES-005 §3.2 stream): onProgress gets {stage, ...}; resolves to the same body as the
// non-streamed answer (blocked included) or throws ApiError for an `event: error` or a non-stream response.
export async function streamChat(path, body, onProgress) {
  const open = () => {
    const headers = { Accept: "text/event-stream", "Content-Type": "application/json" };
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    return fetch(path, { method: "POST", headers, credentials: "same-origin", body: JSON.stringify({ ...body, stream: true }) });
  };
  let response = await open();
  if (!(response.headers.get("content-type") || "").startsWith("text/event-stream")) {
    let payload = await response.json().catch(() => null);
    if (response.status === 401 && payload?.error?.code === "TOKEN_EXPIRED" && (await refresh())) {
      response = await open();
      if (!(response.headers.get("content-type") || "").startsWith("text/event-stream")) {
        payload = await response.json().catch(() => null);
        throw new ApiError(response.status, payload, response.headers);
      }
    } else {
      throw new ApiError(response.status, payload, response.headers);
    }
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const result = { content: "" };
  for (;;) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    let cut;
    while ((cut = buffer.indexOf("\n\n")) >= 0) {
      const block = buffer.slice(0, cut);
      buffer = buffer.slice(cut + 2);
      const name = (block.match(/^event: (.+)$/m) || [])[1];
      const data = JSON.parse((block.match(/^data: (.+)$/m) || [, "null"])[1]);
      if (name === "progress") onProgress(data);
      else if (name === "meta") Object.assign(result, data);
      else if (name === "delta") result.content += data.content;
      else if (name === "done") return Object.assign(result, data);
      else if (name === "error") {
        const headers = new Headers({ "x-request-id": data.request_id || "" });
        if (data.retry_after) headers.set("retry-after", String(data.retry_after));
        throw new ApiError(data.status, { error: { code: data.code, message: data.message } }, headers);
      }
    }
    if (done) throw new ApiError(502, null, response.headers); // stream ended without done/error
  }
}
