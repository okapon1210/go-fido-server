## 登録の流れ

1. RP が PublicKeyCredentialCreationOptions 構造体を作り options に代入しブラウザに渡す
2. ブラウザは受け取った options を publicKey として navigator.credentials.create() を実行する
3. navigator.credentials.create() の戻り値を credential に代入する
4. credential.response を response に代入する
5. credential.getClientExtensionResults() の戻り値を clientExtensionResults に代入する
6. response.clientDataJSON の値を UTF-8 デコードした結果を JSONtext に代入する
7. JSONtext を JSON としてパースした結果を C に代入する
8. C を検証する
   1. C.type が webauthn.create であるか
   2. C.Challenge が options.challenge が base64 エンコードした値と同じか
   3. C.origin が RP の期待するオリジンか
9. response.clientDataJSON を SHA-256 でハッシュ化した結果を hash に代入する
10. attestationObject を CBOR デコードし fmt, authData, attStmt を取得する
11. authData の rpIdHash が RP が期待する RP ID を RP ID を SHA-256 でハッシュ化した値と同じか検証する
12. authData の UP フラグが設定されていることを確認する

## 認証の流れ

## わからん

- attestationObject を CBOR デコードするときの型
- authData 内の ATTESTED CRED. DATA と EXTENSIONS の境界はどうやって識別するのか
  - variable (if present) ってなんだ
  - If the AT and ED flags are not set, it is always 37 bytes long.
  - AT と ED が両方 true だったら境界はどこだ？
- AttestedCredentialData のパースがめんどい
