/**
 * utils.ts
 * Shared response helpers and CORS configuration.
 */

export const corsHeaders: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
  "Access-Control-Max-Age": "86400",
};

export function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

export function errorResponse(message: string, status: number, details?: unknown): Response {
  return jsonResponse(
    {
      error: true,
      message,
      status,
      ...(details !== undefined ? { details } : {}),
      timestamp: new Date().toISOString(),
    },
    status
  );
}
