Keystore2でキー要素漏出の問題が起きている。この問題は高い再現性がある。
DEKを使ってキーを暗号化するだけの以下のようなコードで発生する。この場合dekBytesが漏出しているのが確認できる。

``` kotlin
for (i in 0..31 step 2) {
 dekBytes[i] = (0x48).toByte()
 dekBytes[i+1] = (0x04).toByte()
}

dekSpec = CleanSecretKeySpec(dekBytes, DEK_ALGORITHM)

dataCipher.init(Cipher.ENCRYPT_MODE, dekSpec)
dataCipher.updateAAD(associatedData)
val encryptedContent = dataCipher.doFinal(plaintext)
val dataIv = dataCipher.iv

masterKey = keyStore.getKey(symmetricMasterKeyAlias, null)
    ?: throw GeneralSecurityException("Symmetric master key not found")
val wrapCipher = Cipher.getInstance(DEK_WRAPPING_CIPHER)
wrapCipher.init(Cipher.ENCRYPT_MODE, masterKey)
val wrappedDek = wrapCipher.doFinal(dekBytes)
val wrapIv = wrapCipher.iv
```
キーダンプからRustのスタックトレースが下記のように入手できた。

66b9c08c: 28c2 3002 38a8 786f 0000 0000 2000 0000  (.0.8.xo.... ...
166b9c09c: 4804 4804 4804 4804 4804 4804 4804 4804  H.H.H.H.H.H.H.H.
166b9c0ac: 4804 4804 4804 4804 4804 4804 4804 4804  H.H.H.H.H.H.H.H.
166b9c0bc: 0000 0000 1869 df6f 0000 0000 40df 3002  .....i.o....@.0.
166b9c0cc: c82a a36f 0000 0000 0000 0000 38a8 786f  .*.o........8.xo
166b9c0dc: 0000 0000 2000 0000 0000 0000 0000 0000  .... ...........
166b9c0ec: 0000 0000 0000 0000 0000 0000 0000 0000  ................
166b9c0fc: 0000 0000 0000 0000 0000 0000 d86a df6f  .............j.o
166b9c10c: 0000 0000 40df 3002 0000 0000 1004 7a6f  ....@.0.......zo
166b9c11c: 0000 0000 1c01 0000 0000 0000 7379 7374  ............syst
166b9c12c: 656d 2f73 6563 7572 6974 792f 6b65 7973  em/security/keys
166b9c13c: 746f 7265 322f 7372 632f 6f70 6572 6174  tore2/src/operat
166b9c14c: 696f 6e2e 7273 3a38 3037 3a20 4b65 7973  ion.rs:807: Keys
166b9c15c: 746f 7265 4f70 6572 6174 696f 6e3a 3a77  toreOperation::w
166b9c16c: 6974 685f 6c6f 636b 6564 5f6f 7065 7261  ith_locked_opera
166b9c17c: 7469 6f6e 0a0a 4361 7573 6564 2062 793a  tion..Caused by:
166b9c18c: 0a20 2020 2045 7272 6f72 3a3a 4b6d 2872  .    Error::Km(r
166b9c19c: 2349 4e56 414c 4944 5f4f 5045 5241 5449  #INVALID_OPERATI
166b9c1ac: 4f4e 5f48 414e 444c 4529 0000 e8e8 af6f  ON_HANDLE).....o

このことからoperation.rsのwith_locked_operationで発生した例外が正しく処理されない。また例外が発生した後正常に
入力されたキー要素がドロップされてないことが原因であることが推測される。

・コードの修正には入らない
・上記の流れからwith_locked_operationが呼ばれる流れを推測して修正点を共有してください
・下記のような修正提案が上がっているが、with_lockedではbuffer.zeroizeすれば十分か?
できればインターフェースは崩したなくのでそうするのが良いと思われる。
・検討した内容を共有してください

```rust
use zeroize::Zeroize;

// 修正案 1: Operationオブジェクト自体（あるいは関連する入力バッファ）が破棄される際に、
// 確実にゼロクリアされるように Drop トレイトを実装する（または ZVec に置き換える）。
impl Drop for KeystoreOperation {
    fn drop(&mut self) {
        // オペレーションが削除(delete)される際、内部にキャッシュされている
        // 機密パラメータや一時バッファがあれば、OSにメモリを返す前に強制ゼロクリアする
        if let Some(ref mut buffer) = self.internal_sensitive_buffer {
            buffer.zeroize();
        }
    }
}

// 修正案 2: with_locked_operation 内のエラーハンドリングパスでのサニタイズ
impl KeystoreOperation {
    pub fn with_locked_operation<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Operation) -> Result<R>,
    {
        let mut op = self.lock_operation()?; // Mutexのロック
        
        match f(&mut op) {
            Ok(result) => Ok(result),
            Err(e) => {
                // 【追加パッチ】 KeyMintから INVALID_OPERATION_HANDLE などのエラーが返った場合
                // オペレーションを delete (prune) する前に、クロージャに渡されていた
                // 入力パラメータのメモリを確実にスクラブ（ゼロクリア）する。
                op.sanitize_sensitive_data();

                // 【追加パッチ】 エラーチェーンのコンテキストに機密データ（生の鍵部品）が
                // 文字列化・バイナリ化されて混入しないよう、エラーメッセージを安全なものに置き換える。
                // (これで「operation handle not valid」の横にDEKが漏れるのを防ぐ)
                Err(e).context("Operation failed and was securely scrubbed.")
            }
        }
    }
}
```



