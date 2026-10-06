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
