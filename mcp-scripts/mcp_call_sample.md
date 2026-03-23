# MCP Tool Call Examples

This document provides sample JSON payloads and command-line usages for interacting with the `mcp_call.sh` wrapper script. This is extremely useful when manually testing the MCP server tools or giving hints to agents about proper payload formats.

## 1. Get UI Dump (`get_ui_dump`)

Retrieves the current UI hierarchy (JSON) and optionally a screenshot image (Base64).

```bash
# Basic UI dump (without image, typical usage)
./scripts/mcp_call.sh get_ui_dump '{"include_image": false}'

# UI dump with base64 screenshot
./scripts/mcp_call.sh get_ui_dump '{"include_image": true}'
```

## 2. Get Agent Version (`get_agent_version`)

Retrieves the version information of the Testbed agent (Mutton Agent) currently running on the device.

```bash
./scripts/mcp_call.sh get_agent_version
```

## 3. Tap (`tap`)

Physically taps the specified (x, y) coordinates.

```bash
# Taps at screen coordinates x: 500, y: 1000
./scripts/mcp_call.sh tap '{"x": 500, "y": 1000}'
```

## 4. Input Text (`input_text`)

Inputs text into the currently focused input field. Automatically escapes spaces and optionally presses the `<ENTER>` key after text entry.

```bash
# Inputs text and automatically presses enter
./scripts/mcp_call.sh input_text '{"text": "Hello World", "press_enter": true}'

# Inputs text without pressing enter
./scripts/mcp_call.sh input_text '{"text": "my_username", "press_enter": false}'
```

## 5. Swipe (`swipe`)

Swipes (scrolls) the screen between the specified coordinates.

```bash
# Swipes up from the middle-bottom to the middle-top (common for scrolling down a page)
./scripts/mcp_call.sh swipe '{"start_x": 500, "start_y": 2000, "end_x": 500, "end_y": 500}'

# Swipes left to right (e.g. going back or changing a carousel)
./scripts/mcp_call.sh swipe '{"start_x": 100, "start_y": 1000, "end_x": 900, "end_y": 1000}'
```

## 6. Press Key (`press_key`)

Sends a physical or system key event.

```bash
# Go Home
./scripts/mcp_call.sh press_key '{"keycode": "HOME"}'

# Go Back
./scripts/mcp_call.sh press_key '{"keycode": "BACK"}'

# Press Enter
./scripts/mcp_call.sh press_key '{"keycode": "ENTER"}'
```

## 7. Get Device Info (`get_device_info`)

Retrieves device hardware and OS information (wrapper for `adb shell getprop`).

```bash
./scripts/mcp_call.sh get_device_info
```

## 8. Clear Logcat (`clear_logcat`)

Clears the device's Logcat buffer (equivalent to `adb logcat -c`).

```bash
./scripts/mcp_call.sh clear_logcat
```

## 9. Get Logcat (`get_logcat`)

Retrieves filtered Logcat lines. This is essential for saving LLM input tokens by returning only what's necessary.

```bash
# Gets 100 lines of Information (I) level logs containing "Auth" keyword across all tags
./scripts/mcp_call.sh get_logcat '{"tags": [], "level": "I", "grep_pattern": "Auth", "max_lines": 100}'

# Gets only logs from specific tags
./scripts/mcp_call.sh get_logcat '{"tags": ["ActivityManager", "AndroidRuntime"], "level": "W", "max_lines": 50}'
```

## 10. Check Testbed Health (`check_testbed_health`)

Checks the health status of the ADB connection, device, and agent process.

```bash
./scripts/mcp_call.sh check_testbed_health
```

## 11. Cleanup Agent (`cleanup_agent`)

Force-stops and cleans up the Mutton Agent process remotely.

```bash
./scripts/mcp_call.sh cleanup_agent
```

## 12. JUnit Test Framework Control (`junit_test_*`)

Control and execute JUnit tests compiled from plugins in the resources directory.

```bash
# 1. Reload the test JARs
./scripts/mcp_call.sh junit_test_reload

# 2. List the loaded tests
./scripts/mcp_call.sh junit_test_list

# 3. Execute a specific test class
./scripts/mcp_call.sh junit_test_execute '{"class_name": "org.example.testbed.MyMdfppTest"}'

# 4. Receive test execution logs and results (poll this until status != Running)
./scripts/mcp_call.sh junit_test_receive '{"last_log_index": 0}'
```
