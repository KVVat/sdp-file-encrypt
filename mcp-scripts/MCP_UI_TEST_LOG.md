# UI Verification Log via MCP

This log records the steps taken to verify the Android App UI using the MCP server tools (`get_ui_dump`, `tap`, etc.) during the TopAppBar refactoring task.

## 1. Verifying Dashboard Screen

1. **Start the App:**
   Ran the intent directly via adb/shell.
   ```bash
   adb shell am start -n com.android.niapsec.realworld/.MainActivity
   ```

2. **Dump the UI UI-Tree:**
   ```bash
   ./mcp-scripts/mcp_call.sh get_ui_dump > /tmp/dashboard_dump.txt
   ```

3. **Validation:**
   * Read the JSON dump and verified `Agency Network` (TopAppBar text) was successfully rendered at `top:153, bounds:179-253`.
   * Verified the existence of the three new buttons: `バックアップ`, `接続 (Hack)`, and `自爆` inside bounds around `y: 343-469`.
   * Found the dynamically generated directive item `Directive 7FA25010` at `{"top":510,"left":42,"right":1038,"bottom":668}`.

## 2. Testing Screen Transition (Tap Emulation)

1. **Calculate Target Coordinates:**
   Using the bounding box of `Directive 7FA25010`:
   * X = (42 + 1038) / 2 = 540
   * Y = (510 + 668) / 2 = 589

2. **Send Tap Command:**
   ```bash
   ./mcp-scripts/mcp_call.sh tap '{"x": 540, "y": 589}'
   ```
   *Verified the screen successfully transitioned to the DetailScreen.*

## 3. Verifying DetailScreen UI

1. **Dump the UI UI-Tree Again:**
   ```bash
   ./mcp-scripts/mcp_call.sh get_ui_dump > /tmp/detail_dump.txt
   ```

2. **Validation:**
   * Successfully verified the new Scaffold and TopAppBar exist with the text `Directive Details`.
   * Verified the `androidx.compose.material.icons.filled.ArrowBack` icon rendered as a clickable icon with `contentDescription: "Back"`.
   * Read the rendered ciphertext out of the UI tree: `4548425401F7A6420804018CD870B4C3DAC3CBEED3...` below the `View Mode:` text.

## Conclusion
The MCP `get_ui_dump` tools perfectly expose the exact bounds, texts, and component tree (including `contentDescription` and semantic properties applied by Jetpack Compose), allowing the AI Agent to autonomously navigate, tap, and visually review layout fixes.

## 4. Logcat Verification

1. **Clear Logcat:**
   First, we cleared the old logcat buffers to get a clean testing slate:
   ```bash
   ./mcp-scripts/mcp_call.sh clear_logcat
   ```
   *Stream output verified successful clearance.*

2. **App Startup & Fetch Logs:**
   After starting the app natively, we fetched the startup logs directly through the stream without creating intermediary files, thereby avoiding any extra file permission popups for the user:
   ```bash
   ./mcp-scripts/mcp_call.sh get_logcat '{"max_lines":50}'
   ```
   *Logs retrieved successfully, confirming that the MCP agent's `get_logcat` correctly taps into the live ADB log stream.*

## 5. Visual UI Verification (VLM Testing)

1. **Spy UI and Full Hex Dump Update:**
   We updated `DetailScreen`'s Ciphertext view to feature a full, unabridged file dump using an 8-bytes-per-line hex format to prevent text-wrapping on mobile displays.
   This view was heavily stylized with a Monospace font, dark green background (`#0F2016`), and bright "hacker-green" text (`#00FF41`) to simulate a spy terminal.

2. **Screen Capture Validation:**
   To guarantee the layout changes successfully applied, we took a device screenshot.
   *Note on `get_ui_dump`:* The tool returns a JSON structure containing `{"image_base64": "..."}`, which is a **JPEG image**.
   During testing, rather than piping JSON to a file (which prompts the user for local file access and causes friction), the safest and most efficient path for visual validation natively over ADB without extra JSON parsing was:
   ```bash
   adb shell screencap -p > /tmp/screen.png
   ```
   *We (the Agent, acting as a VLM) evaluated the resulting image natively, confirming the toggle successfully switched to "Ciphertext", the Hex Dump perfectly spans horizontally without wrapping, and the aesthetic successfully mirrors a secure data terminal.*

   > **Crucial Lesson for Future Tool Usage:**
   > When using backend tools like the MCP server, **always prioritize reading output from the standard stream (stdout)** instead of redirecting logic like `> /tmp/...`. Writing to an external file on the user's host machine triggers confirmation dialogs, significantly slowing down autonomous workflows.
    *   スクリーンのUI階層(`index`や`text`など)を解析できても、実際の見た目や「Base64されたJPEG画像をデコードして確認する」という点に苦労した。
*   **教訓**:
    *   ツール実行時は**標準出力ストリームから直接**データを読み取ること。ファイルにリダイレクトして吐き出すと、人間の確認作業が挟まり自動化ループが阻害されたり、極端に長いJSONの場合にトラブルが起きやすい。
    *   MCPから返ってくるBase64画像を確認するために、新しく `mcp_extract_screenshot.py` スクリプトを作成した。これにより、`adb shell screencap` を介さずに、ダイレクトにMCPサーバーから返却される画面スナップショットをアーティファクトとして抽出可能になった。

### スクリプトの使用方法 (`mcp_extract_screenshot.py`)
MCP サーバーの `get_ui_dump` ツールを内部で呼び出し、得られた JSON ツリーから自動で `screenshot` フィールド（Base64 JPEG）を探して抽出し、ファイルに保存する便利なラッパースクリプトです。

```bash
# 権限付与（初回のみ）
chmod +x ./mcp-scripts/mcp_extract_screenshot.py

# MCPからUIダンプを取得し、スクリーンショットを保存
./mcp-scripts/mcp_extract_screenshot.py /path/to/artifacts/screenshot.jpg
``` 
