import { evaluate } from "./policy.js";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...CORS },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (url.pathname === "/" && request.method === "GET") {
      return json({ ok: true, endpoint: "POST /release-gate" });
    }

    if (url.pathname !== "/release-gate") {
      return json({ error: "not_found" }, 404);
    }

    if (request.method !== "POST") {
      return json({ error: "method_not_allowed" }, 405);
    }

    let payload;
    try {
      payload = await request.json();
    } catch {
      payload = {};
    }

    return json(evaluate(payload));
  },
};
