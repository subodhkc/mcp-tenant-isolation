// Test fixture: Non-MCP file using apiKey
// Should NOT trigger MCP-004 or MCP-008 (no MCP context)

export async function callExternalApi() {
  const apiKey = process.env.EXTERNAL_API_KEY;
  const response = await fetch('https://api.example.com/data', {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  return response.json();
}
