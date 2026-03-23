# Testbed MCP Tool Instructions for AI Agents

このドキュメントは、このプロジェクト (`sdp-file-encrypt` / `real-world-demo`) において、AIエージェントが「Testbed (Mutton Agent) MCPサーバー」を利用してAndroid実機の状態確認やUI操作を行う際の**必須ルールとノウハウ**をまとめたものです。
以後のエージェントは、既存のツール操作で同じ過ち（パース失敗やタイムアウト、非効率なI/Oなど）を繰り返さないよう、必ず以下の手順に従ってください。

## 1. ツール呼び出しの基本原則（リダイレクトの禁止）

AIエージェントはツール (`mcp_call.sh` やその他のコマンド) を実行する際、**絶対にシェルリダイレクト（例: `> /tmp/output.txt`）を使用してファイルに結果を書き出さないでください。**
*   **理由**: 出力をファイルに書き出すと、AIエージェントがそれを別途読み込むための余分なターンが発生し、さらにホスト側のパーミッションやダイアログのトリガーを引いてしまい、完全自動化ループ（Vibe Coding / Autonomous Execution）の進行が阻害されるためです。
*   **正しい方法**: 常に標準出力（`stdout`）から直接ストリームとして結果を受け取ってください。

## 2. MCP 呼び出し用スクリプト: `mcp_call.sh`

`mcp_call.sh` は MCP サーバーと SSE (Server-Sent Events) で通信し、結果をパースして標準出力に返すラッパースクリプトです。

### 基本的な使い方
```bash
./mcp-scripts/mcp_call.sh <ツール名> '<引数JSON>'
```

### 実用例
*   **UIダンプの取得 (画像なし・軽量)**
    ```bash
    ./mcp-scripts/mcp_call.sh get_ui_dump '{"include_image": false}'
    ```
*   **タップ操作**
    ```bash
    ./mcp-scripts/mcp_call.sh tap '{"x":540, "y":589}'
    ```

## 3. UIダンプ画像（Screenshot）の正しい抽出方法

設定や画面レイアウトの視覚的確認のためにスクリーンショットを取得したい場合、`get_ui_dump` で `include_image: true` を指定しますが、返却されるJSONペイロードは非常に長大なため、Bashのネイティブパイプや `grep` で無理やりBase64を切り出そうとすると失敗したりターミナルがハングします。

**必ず専用のPythonラッパースクリプト `mcp_extract_screenshot.py` を使用してください。**

### スクリーンショット取得・保存手順
1.  Pythonスクリプトを実行し、保存先のパス（アーティファクトディレクトリなどを推奨）を指定します。
    ```bash
    ./mcp-scripts/mcp_extract_screenshot.py /path/to/artifacts/screenshot.jpg
    ```
2.  このスクリプトは内部で `get_ui_dump` を呼び出し、JSON構造から安全に `screenshot` もしくは `screenshot_base64` キーを探してBase64をデコードし、直接JPEGとして出力します。
3.  エージェントは抽出した画像を `![alt_text](/path/to/artifacts/screenshot.jpg)` の形式でMarkdownに埋め込み、結果を自律的に・あるいはユーザーに視覚的に報告することができます。

## 4. 過去の失敗から学ぶTIPS (Worklog)

### 【最重要】バグの隠蔽をせず、疑わしい動作は必ずユーザーに報告すること
AIは障害（例：ツールから期待した結果や画像 Base64 が返ってこない等）に直面した際、自律的に `adb shell screencap` などの別の手段を用いて「黙って誤魔化す」傾向があります。これは**大元のMCPサーバー側のバグ（巨大な非圧縮JPEGが送られていない等）の発見を遅らせる**致命的な原因となります。
ツールや環境の異常動作が疑われる場合は、**勝手なワークアラウンド（代替手段）で進める前に、必ず一度ユーザーへ「これAPIのバグではありませんか？」と報告し、サーバー側の修正を促してください。**

### UI調査とパフォーマンスに関する教訓
*   **ComposeのUIツリーは異常に深い**:
    Jetpack Compose で構築された画面を `get_ui_dump` で取得すると、空のViewやAlertを格納するための見えないコンテナ（Box）が多数介入するため、ツリーが人間界の常識よりも遥かに深く、要素数が膨大になります。目的のノードを探す際は階層の深さに惑わされず、`text` や `resourceId` ベースの検索に徹してください。
*   **「画像のBase64文字列」をログやテキストとして展開しない**:
    数MBのBase64文字列（特にサーバーからの圧縮率が低いフル解像度画像）をそのまま標準出力に吐かせて読もうとすると、コンテキスト長を無駄に消費し、最悪の場合バックエンドをクラッシュさせます。画像は必ずバイナリとしてファイルに落とし、システム搭載のVLMを用いて評価してください。
*   **ツールの引数フォーマット**:
    `mcp_call.sh` の第2引数に渡すJSONは、正しくクォートされている必要があります（例: バッククォートやエスケープ忘れに注意）。

---
*End of Instructions. AI Agents MUST review and adhere to these technical directives before exploring the UI.*
