// fix-10: Cloudflare Worker die als proxy dient naar de Anthropic API.
// Voorkomt CORS-blokkade die ontstond doordat de browser rechtstreeks
// api.anthropic.com aanriep (zie sendMessage / generateDocument in index.html).
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/claude" && request.method === "POST") {
      if (!env.ANTHROPIC_API_KEY) {
        return new Response(
          JSON.stringify({ error: "ANTHROPIC_API_KEY ontbreekt in de Worker-configuratie." }),
          { status: 500, headers: corsHeaders() }
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

    if (url.pathname === "/api/claude" && request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
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
    "Access-Control-Allow-Headers": "Content-Type",
  };
}
