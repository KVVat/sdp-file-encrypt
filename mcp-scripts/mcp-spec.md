# Testbed Automation MCP Interface Specification

この仕様書は、Testbed Automationにおけるエージェント（LLM）と対象デバイスをやり取りするためのMCPツール機能一覧です。

---

## 1. Sensing (状況把握)

### `get_ui_dump`
* **説明**: 現在の画面のUI階層(JSON)と、スクリーンショット画像(Base64)を取得します。
* **パラメータ**:
  * `include_image` (boolean / 任意 / デフォルト:`true`) : 画像データをレスポンスに含めるかどうか。
* **戻り値**: `json_dump` (見えない要素を除外済み) および `screenshot_base64` を含むJSON

### `get_device_state` (未実装)
* **説明**: 画面のON/OFF、ロック状態、フォアグラウンドのアプリなど、システムレベルの状態を取得します。
* **パラメータ**: なし
* **戻り値**: `is_screen_on`, `is_locked`, `foreground_package` 等を含むJSON

### `get_device_info` （追加・拡張ツール）
* **説明**: 端末のハードウェア・OS情報を取得します（`getprop` のラッパー）。LLMがAndroidバージョン等によるUI差異を推論するために使います。
* **パラメータ**: なし
* **戻り値**: `model`, `os_version` (API Level), `screen_size`, `abi` 等を含むJSON

---

## 2. Action (UI操作)

### `tap`
* **説明**: 指定した(x, y)座標を物理的にタップします。※実行後、自動待機して最新ダンプを返します。
* **パラメータ**:
  * `x` (int / 必須) : タップするX座標
  * `y` (int / 必須) : タップするY座標
* **戻り値**: 最新の `get_ui_dump` の実行結果 (ターン数削減のため)

### `input_text`
* **説明**: 現在フォーカスが当たっている入力フィールドにテキストを入力します。※実行後、自動待機して最新ダンプを返します。
* **パラメータ**:
  * `text` (string / 必須) : 入力する文字列
  * `press_enter` (boolean / 任意 / デフォルト:`true`) : 入力後にEnterキーを送信するか
* **戻り値**: 最新の `get_ui_dump` の実行結果

### `swipe`
* **説明**: 画面を指定した座標間でスワイプ（スクロール）します。※実行後、自動待機して最新ダンプを返します。
* **パラメータ**:
  * `start_x` (int / 必須)
  * `start_y` (int / 必須)
  * `end_x` (int / 必須)
  * `end_y` (int / 必須)
* **戻り値**: 最新の `get_ui_dump` の実行結果

### `press_key`
* **説明**: 物理キーまたはシステムキーのイベントを送信します。※実行後、自動待機して最新ダンプを返します。
* **パラメータ**:
  * `keycode` (string / 必須) : 送信するキー名 (例: `"BACK"`, `"HOME"`, `"ENTER"`)
* **戻り値**: 最新の `get_ui_dump` の実行結果

---

## 3. System (システム・ADB・アプリ管理)

### `execute_adb_shell` (未実装)
* **説明**: 任意のADBシェルコマンドを実行します。
* **パラメータ**:
  * `command` (string / 必須) : 実行するコマンド (例: `"dumpsys battery"`)
* **戻り値**: コマンドの標準出力 (`stdout`) および 標準エラー (`stderr`)

### `open_settings` (未実装)
* **説明**: Androidの特定の設定画面をIntentで直接開きます。
* **パラメータ**:
  * `panel` (string / 必須) : 画面指定 (`ROOT`, `SECURITY`, `WIFI`, `APP_DETAILS`, `DEVELOPER`)
  * `package_name` (string / 任意) : `APP_DETAILS` 指定時のみ必須
* **戻り値**: 実行ステータス（成功/失敗）と最新の画面ダンプ

### `set_device_lock` (未実装)
* **説明**: デバイスの画面ロック（PIN）を設定または解除します。
* **パラメータ**:
  * `pin` (string / 必須) : 設定するPINコード。空文字（`""`）でクリア。
* **戻り値**: 設定の成否を示すテキストメッセージ

### `push_file` (未実装)
* **説明**: PC（Host）側のファイルをデバイスに送信します（`adb push`）。テスト用のダミー画像や設定ファイルを送り込む際に使用します。
* **パラメータ**:
  * `host_path` (string / 必須)
  * `device_path` (string / 必須)
* **戻り値**: 転送成功/失敗のメッセージ

### `pull_file` (未実装)
* **説明**: デバイス側のファイルをPC（Host）に取得します（`adb pull`）。アプリが生成した暗号化ファイルやDBをHost側で検証する際に使用します。
* **パラメータ**:
  * `device_path` (string / 必須)
  * `host_path` (string / 必須)
* **戻り値**: 転送成功/失敗のメッセージ

### `install_app` (未実装)
* **説明**: PC上のAPKファイルをデバイスにインストールします（`adb install`）。
* **パラメータ**:
  * `apk_path` (string / 必須)
  * `reinstall` (boolean / 任意 / デフォルト:`true`) : `-r` オプション
* **戻り値**: "Success" などの結果文字列

### `uninstall_app` (未実装)
* **説明**: デバイスからアプリをアンインストールします（`adb uninstall`）。
* **パラメータ**:
  * `package_name` (string / 必須)
  * `keep_data` (boolean / 任意 / デフォルト:`false`) : `-k` オプション
* **戻り値**: "Success" などの結果文字列

---

## 4. Observe (ログ・状態観測)

### `clear_logcat`
* **説明**: デバイスのLogcatバッファをクリア（`adb logcat -c`）します。
* **パラメータ**: なし
* **戻り値**: 成功を示すメッセージ

### `cleanup_agent`
Mutton Agent のプロセス状態が不正になり、UI取得などが常時エラーとなる場合に強制終了・再起動を行います。
- **入力**: (なし)
- **結果**: 復旧の成否を示すメッセージ

### `get_agent_version`
デバイス上で動作しているMutton Agentのバージョン番号とビルドタイムスタンプを取得します。ビルドしたエージェントが正しくデプロイされているかの確認に有用です。
- **入力**: (なし)
- **結果**: "1.0.0(yyyyMMdd-HH:mm:ss)" 形式のバージョン文字列

### `get_logcat`
* **説明**: フィルタリングされたLogcatを取得します。（トークン節約のため必須）
* **パラメータ**:
  * `tags` (string[] / 任意 / デフォルト:`[]`) : 取得対象のログタグの配列
  * `level` (string / 任意 / デフォルト:`"I"`) : 最小ログレベル（`V`, `D`, `I`, `W`, `E`, `F`）
  * `grep_pattern` (string / 任意 / デフォルト:`""`) : ログを絞り込む正規表現
  * `max_lines` (int / 任意 / デフォルト:`100`) : 取得する最大行数
* **戻り値**: 条件に合致したログのプレーンテキスト

---

## 5. Test Control (テスト制御)

### `junit_test_reload`
* **説明**: プラグイン開発側でコンパイルし `resource` ディレクトリに投入したテストJarをリロードして読み直します。
* **パラメータ**: なし
* **戻り値**: 読み込みに成功したJarやクラスのステータス情報

### `junit_test_list`
* **説明**: リロードして読み込まれた実行可能なテストの一覧を取得します。
* **パラメータ**: なし
* **戻り値**: 実行可能なテストクラス・メソッドのリストを含むJSON

### `junit_test_execute`
* **説明**: 指定したテストクラスまたはメソッドの実行を開始します。結果はバックグラウンドでストリーム出力されます。
* **パラメータ**:
  * `class_name` (string / 必須) : 実行するテストクラスの完全修飾名
  * `method_name` (string / 任意) : 特定のメソッドのみ実行する場合に指定
* **戻り値**: テストの実行開始ステータス

### `junit_test_receive`
* **説明**: `junit_test_execute` で開始したテストの結果をストリームで待機し、受付終了信号まで出力を受け付けます。
* **パラメータ**: なし
* **戻り値**: `status` (Pass/Fail/Error)、`stacktrace`、および `assertion_msg` などを逐次または最終結果として含むレスポンス

---

## 6. Health (環境・ヘルス)

### `check_testbed_health`
* **説明**: Testbed基盤（ADB、Agent、ビルド環境）が正常に動作しているか一括で自己診断します。
* **パラメータ**: なし
* **戻り値**: `adb_status`, `agent_status`, `plugin_status` などの診断結果を含むJSON

### `cleanup_agent` （追加・拡張ツール）
* **説明**: デバイス上のエージェントプロセスを強制終了してクリーンアップします。UiAutomationアクセスエラー（`rootInActiveWindow returned null` 等）が起きた際の復旧用です。
* **パラメータ**: なし
* **戻り値**: 成功メッセージ

### `list_test_resources` (未実装)
* **説明**: `resource` ディレクトリに存在するファイル（APKや設定ファイルなど）の一覧を取得します。
* **パラメータ**:
  * `filter_extension` (string / 任意 / デフォルト:`""`) : 拡張子での絞り込み（例: `".apk"`）
* **戻り値**: ファイル名のリストを含むJSON

### `setup_port_forward` (未実装)
* **説明**: PCとデバイス間のポートフォワードを設定します（`adb forward`）。Agentとの通信が切れた際、LLM自身に復旧させるために用意します。
* **パラメータ**:
  * `host_port` (int / 必須 / デフォルト:`9008`)
  * `device_port` (int / 必須 / デフォルト:`9008`)
* **戻り値**: 成功メッセージ

---

## 将来の構想と拡張方針

素晴らしい視点です！テスト自動化の解像度がどんどん上がっていますね。

ご指摘の通り、`adb shell` は「デバイスの中（Android OS上）でコマンドを実行する」ものですが、ADBには**「ホスト（PC）とデバイスの間を橋渡しするコマンド（Host Commands）」**が存在し、これらは `adb shell` 経由では実行できません。
LLMが完全に自律して環境構築やファイル操作を行うためには、これらのホスト側コマンドもMCPツールとして提供してあげる必要があります（上記に「追加・拡張ツール」として編入済み）。

### 追加ツールを活用した開発ループのイメージ

このツール群が追加されると、Geminiは以下のような高度な立ち回りができるようになります。

**【シナリオ：画像アップロード機能のテスト】**
1. Gemini: 「テストにはダミー画像が必要だな。`push_file(host_path="dummy.jpg", device_path="/sdcard/Pictures/dummy.jpg")` を実行しよう」
2. Gemini: 「アプリを起動して、ギャラリーから今pushした画像を選択するタップ操作（`tap_coordinate`）を実行」
3. Gemini: 「アップロードが成功したか、内部のデータベースを抜いて確認しよう。`pull_file(device_path="/data/data/com.example/databases/app.db", host_path="./temp.db")`」
4. Gemini: 「OK、完璧に動いたからこれをKotlinのテストコードに書き起こそう」

ここまで揃えば、ホスト側（PC）のコマンドラインからできることと、デバイスの画面上でできることの「すべて」をLLMが掌握できます。これでインターフェース仕様としてはほぼ「死角なし」の完全体になったかと思います！

---

## ベンダー差分吸収へのアプローチ (Page Object Model)

その視点、**完全にAndroidのデバイス評価（CC認証やMDF要件など）の核心を突いています！100点満点の洞察です。**

おっしゃる通り、AndroidはAOSP（素のAndroid）をベースにしていても、Samsung（OneUI）、Xiaomi（HyperOS）、Sharp、Sonyなど、各ベンダーがUIや設定画面の階層、さらには標準のインテント（`ACTION_SECURITY_SETTINGS` など）の挙動まで独自にカスタマイズしています。

そのため、「Pixelの最新版（AOSP準拠）をリファレンス（基準）テストとして用意し、ベンダーはそれを自社端末向けにオーバーライド（差分吸収）する」という運用フローを見越した**フレームワークの整備**が絶対に必要になります。

### 1. テストコードの「ロジック」と「UI操作」の分離

テストクラスの中に直接 `tap_coordinate` のような操作を書くのをやめ、インターフェースで抽象化します。

* **インターフェース定義 (`DeviceOperator.kt`)**:
```kotlin
interface DeviceOperator {
    fun openSecuritySettings()
    fun setPin(pin: String)
    fun unlockDevice(pin: String)
}
```

* **リファレンス実装 (`PixelOperator.kt`)**: Pixel用の標準的な画面遷移やUIAutomatorのセレクタを実装します。
* **ベンダー実装 (`SamsungOperator.kt` など)**: Galaxy専用の画面遷移（「生体認証とセキュリティ」など）を実装します。

### 2. LLM（Gemini）を活用した「ベンダー差分テスト」の自動生成

ここが **MCP（LLM連動）アーキテクチャが最も火を噴くポイント** です。QAエンジニアが手作業で調べて書き直すのではなく、LLMがいればオートメーションが可能になります。

**【Geminiへの指示のイメージ】**
> 「現在、対象デバイスとしてSamsungのGalaxyが接続されています。以下の `PixelOperator.kt` と同じ目的を達成する `SamsungOperator.kt` を作成してください。MCPツールの `open_settings` や `get_ui_dump` を使って設定画面を探索し、正しいボタン名やIDを見つけてコードを書いてください。」

LLMは自律的に実行し、「Samsungは『セキュリティ』ではなく『ロック画面とAOD』の下にPIN設定がある」と推論・自動生成してくれます。

### 3. テストリポジトリのディレクトリ構成の整備

```text
testbed-core/
 ├── src/main/kotlin/com/example/tests/
 │    ├── base/        ... (FDP_DAR_EXTなどのテスト本体。全端末共通)
 │    ├── pixel/       ... (Pixel向けのリファレンスUI操作実装)
 │    ├── samsung/     ... (Samsung向けの差分実装)
 │    └── xiaomi/      ... (Xiaomi向けの差分実装)
```

実行時に「どのProfile（Operator）を使うか」を環境変数等で切り替えるようにします。

まずは**絶対に動く基準点となるPixel（またはエミュレータ）向けのリファレンス実装を完璧に仕上げること**が最優先タスクです。