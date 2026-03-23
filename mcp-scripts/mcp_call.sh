#!/bin/bash
# =========================================================
# MCP Tool Caller Wrapper for Agents (e.g., Jetski / Cline)
# =========================================================
# Usage:
#   ./scripts/mcp_call.sh <tool_name> [arguments_json]
#
# Examples:
#   ./scripts/mcp_call.sh tools/list
#   ./scripts/mcp_call.sh get_logcat '{"tags":["ActivityManager"], "level":"I", "max_lines":5}'
# =========================================================

TOOL_NAME=$1
TOOL_ARGS=${2:-"{}"}

if [ -z "$TOOL_NAME" ]; then
    echo "Usage: ./mcp_call.sh <tool_name> [arguments_json]"
    echo "Example: ./mcp_call.sh get_logcat '{\"max_lines\":5}'"
    exit 1
fi

# 1. Connect to SSE
rm -f /tmp/mcp_call_sse_out_$$
curl -sN http://localhost:11452/mcp > /tmp/mcp_call_sse_out_$$ &
SSE_PID=$!
sleep 1.5

# 2. Extract Session ID (Removing Carriage Returns)
SESSION_INFO=$(grep "^data: " /tmp/mcp_call_sse_out_$$ | head -n 1 | sed 's/^data: //' | tr -d '\r')

if [ -z "$SESSION_INFO" ]; then
    echo "Error: Failed to connect to local MCP server at localhost:11452"
    kill $SSE_PID 2>/dev/null
    exit 1
fi

MSG_ENDPOINT="http://localhost:11452${SESSION_INFO}"

# 3. Build JSON-RPC Payload
if [ "$TOOL_NAME" == "tools/list" ]; then
    PAYLOAD=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": 1
}
EOF
)
else
    PAYLOAD=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "id": 1,
  "params": {
    "name": "$TOOL_NAME",
    "arguments": $TOOL_ARGS
  }
}
EOF
)
fi

# 4. Dispatch the Request
curl -s -X POST "$MSG_ENDPOINT" \
     -H "Content-Type: application/json" \
     -d "$PAYLOAD" > /dev/null

# Wait for the response to arrive in the SSE stream
sleep 1.5

# 5. Output the result from the stream
echo "--- raw SSE stream ---"
cat /tmp/mcp_call_sse_out_$$

# Cleanup
kill $SSE_PID 2>/dev/null
rm -f /tmp/mcp_call_sse_out_$$
