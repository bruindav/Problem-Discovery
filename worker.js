// fix-10: Cloudflare Worker die als proxy dient naar de Anthropic API.
// Voorkomt CORS-blokkade die ontstond doordat de browser rechtstreeks
// api.anthropic.com aanriep (zie sendMessage / generateDocument in index.html).
//
// fix-22: /api/claude accepteert alleen aanroepen met een geldig Firebase
// ID-token van een geautoriseerd e-mailadres. Dit voorkomt dat iemand die de
// Worker-URL kent (ook zonder in te loggen in de app) rechtstreeks de
// Anthropic API aanroept op jouw kosten.
const FIREBASE_PROJECT_ID = "problemanalyses";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/claude" && request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    if (url.pathname === "/api/claude" && request.method === "POST") {
      if (!env.ANTHROPIC_API_KEY) {
        return new Response(
          JSON.stringify({ error: "ANTHROPIC_API_KEY ontbreekt in de Worker-configuratie." }),
          { status: 500, headers: corsHeaders() }
        );
      }

      const authHeader = request.headers.get("Authorization") || "";
      const idToken = authHeader.replace(/^Bearer\s+/i, "").trim();
      if (!idToken) {
        return new Response(
          JSON.stringify({ error: "Niet ingelogd." }),
          { status: 401, headers: corsHeaders() }
        );
      }

      let claims;
      try {
        claims = await verifyFirebaseIdToken(idToken, FIREBASE_PROJECT_ID);
      } catch (err) {
        return new Response(
          JSON.stringify({ error: "Ongeldige of verlopen login: " + err.message }),
          { status: 401, headers: corsHeaders() }
        );
      }

      const allowedEmails = (env.ALLOWED_EMAILS || "")
        .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
      const email = (claims.email || "").toLowerCase();
      if (allowedEmails.length > 0 && !allowedEmails.includes(email)) {
        return new Response(
          JSON.stringify({ error: `Dit account (${claims.email}) is niet geautoriseerd voor deze app.` }),
          { status: 403, headers: corsHeaders() }
        );
      }

      try {
        const body = await request.text();
        const upstream = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": env.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
          },
          body,
        });
        const text = await upstream.text();
        return new Response(text, {
          status: upstream.status,
          headers: corsHeaders(),
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ error: "Proxy-fout: " + err.message }),
          { status: 502, headers: corsHeaders() }
        );
      }
    }

    // Alle overige requests: serveer de statische bestanden (index.html etc.)
    return env.ASSETS.fetch(request);
  },
};

function corsHeaders() {
  return {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function base64UrlDecodeToString(str) {
  return new TextDecoder().decode(base64UrlDecode(str));
}

// Verifieert een Firebase Auth ID-token zelf, met Web Crypto en Google's
// publieke sleutels (JWK-formaat) — zonder een Firebase Admin SDK nodig te
// hebben, wat in een Cloudflare Worker niet beschikbaar is.
async function verifyFirebaseIdToken(idToken, projectId) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [headerB64, payloadB64, sigB64] = parts;

  const header = JSON.parse(base64UrlDecodeToString(headerB64));
  const payload = JSON.parse(base64UrlDecodeToString(payloadB64));

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) throw new Error("token verlopen");
  if (payload.iat > now + 300) throw new Error("token iat in de toekomst");
  if (payload.aud !== projectId) throw new Error("verkeerde audience");
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) throw new Error("verkeerde issuer");
  if (!payload.sub) throw new Error("geen subject");

  const jwksResp = await fetch(
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
  );
  if (!jwksResp.ok) throw new Error("kon Google's sleutels niet ophalen");
  const jwks = await jwksResp.json();
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid);
  if (!jwk) throw new Error("geen passende sleutel gevonden");

  const key = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
  );
  const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlDecode(sigB64);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
  if (!valid) throw new Error("ongeldige handtekening");

  return payload;
}
