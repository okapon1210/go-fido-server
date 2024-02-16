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
  - PubKey の中に長さが入っている
    - CBOR の UnmarshalFirst を使えば分割できそう
- AttestedCredentialData のパースがめんどい
- CDDL 読めない...
  - CBOR を表現するための記法なのでこれ使ったら JSON も定義いける

## [Web Authentication: An API for accessing Public Key Credentials Level 3](https://www.w3.org/TR/webauthn-3/)

### [7. WebAuthn Relying Party Operations](https://www.w3.org/TR/webauthn-3/#sctn-rp-operations)

> A [registration](https://www.w3.org/TR/webauthn-3/#registration-ceremony) or [authentication ceremony](https://www.w3.org/TR/webauthn-3/#authentication-ceremony) begins with the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-3/#webauthn-relying-party) creating a PublicKeyCredentialCreationOptions or [PublicKeyCredentialRequestOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions) object, respectively, which encodes the parameters for the ceremony. The Relying Party SHOULD take care to not leak sensitive information during this stage; see [§ 14.6.2 Username Enumeration](https://www.w3.org/TR/webauthn-3/#sctn-username-enumeration) for details.

登録または認証セレモニーは、WebAuthn Relying Party がそれぞれ PublicKeyCredentialCreationOptions または PublicKeyCredentialRequestOptions オブジェクトを作成することから始まる。詳細については 14.6.2節 Username Enumeration を参照のこと。

> Upon successful execution of [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) or [get()](https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get), the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party)'s script receives a [PublicKeyCredential](https://www.w3.org/TR/webauthn-3/#publickeycredential) containing an [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse) or [AuthenticatorAssertionResponse](https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse) structure, respectively, from the client. It must then deliver the contents of this structure to the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) server, using methods outside the scope of this specification. This section describes the operations that the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) must perform upon receipt of these structures.

create()またはget()の実行に成功すると、Relying Partyのスクリプトは、それぞれAuthenticatorAttestationResponseまたはAuthenticatorAssertionResponse構造体を含むPublicKeyCredentialをクライアントから受け取る。その後、本仕様の範囲外のメソッドを使用して、この構造体のコンテンツをRelying Partyサーバーに配信する必要がある。このセクションでは、これらの構造体を受け取ったときに信頼当事者が実行しなけ ればならない操作について説明する。

#### [7.1. Registering a New Credential](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)

> In order to perform a [registration ceremony](https://www.w3.org/TR/webauthn-3/#registration-ceremony), the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) MUST proceed as follows:

登録セレモニーを行うために、Relying Partyは以下の手続きを行わなければならない：

> 1. Let options be a new [PublicKeyCredentialCreationOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions) structure configured to the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party)'s needs for the ceremony.

1. optionsを、セレモニーに対するRelying Partyのニーズに合わせて構成された新しいPublicKeyCredentialCreationOptions構造体とする。

> 2. Call [navigator.credentials.create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) and pass options as the [publicKey](https://www.w3.org/TR/webauthn-3/#dom-credentialcreationoptions-publickey) option. Let credential be the result of the successfully resolved promise. If the promise is rejected, abort the ceremony with a user-visible error, or otherwise guide the user experience as might be determinable from the context available in the rejected promise. For example if the promise is rejected with an error code equivalent to "[InvalidStateError](https://webidl.spec.whatwg.org/#invalidstateerror)", the user might be instructed to use a different [authenticator](https://www.w3.org/TR/webauthn-3/#authenticator). For information on different error contexts and the circumstances leading to them, see [§ 6.3.2 The authenticatorMakeCredential Operation.](https://www.w3.org/TR/webauthn-3/#sctn-op-make-cred)

2. navigator.credentials.create()を呼び出し、publicKeyオプションとしてoptionsを渡す。resolveされたpromiseの結果をcredentialとする。promiseが拒否された場合、ユーザーから見えるエラーでセレモニーを中止するか、拒否されたpromiseで利用可能なコンテキストから判断可能なユーザーエクスペリエンスをガイドします。例えば、"InvalidStateError"と同等のエラーコードでpromiseが拒否された場合、ユーザは別の認証器を使用するように指示されるかもしれない。さまざまなエラーコンテキストとそれに至る状況については、セクション6.3.2 authenticatorMakeCredentialオペレーションを参照のこと。

> 3. Let response be credential.[response](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response). If response is not an instance of [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse), abort the ceremony with a user-visible error.

3. response を credential.response とする。responseがAuthenticatorAttestationResponseのインスタンスでない場合、ユーザーから見えるエラーでセレモニーを中断する。

> 4. Let clientExtensionResults be the result of calling credential.[getClientExtensionResults()](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-getclientextensionresults).

4. clientExtensionResultsを、credential.getClientExtensionResults()を呼び出した結果とする。

> 5. Let JSONtext be the result of running [UTF-8 decode](https://encoding.spec.whatwg.org/#utf-8-decode) on the value of response.[clientDataJSON](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson).

5. response.clientDataJSONの値をUTF-8デコードした結果をJSONtextとする。

> NOTE: Using any implementation of [UTF-8 decode](https://encoding.spec.whatwg.org/#utf-8-decode) is acceptable as long as it yields the same result as that yielded by the [UTF-8 decode](https://encoding.spec.whatwg.org/#utf-8-decode) algorithm. In particular, any leading byte order mark (BOM) MUST be stripped.

注意: UTF-8デコードの実装は、UTF-8デコードアルゴリズムがもたらす結果と同じ結果をもたらす限り、どのような実装を使用しても構わない。特に、先頭のバイトオーダーマーク(BOM)は取り除かれなければならない(MUST)。

> 6. Let C, the [client data](https://www.w3.org/TR/webauthn-3/#client-data) claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.

6. クレデンシャル作成時に収集されたクライアントデータをCとすると、実装固有のJSONパーサをJSONtext上で実行した結果である。

> NOTE: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.

注：Cは、このアルゴリズムが要求するように、Cの構成要素が参照可能である限り、どのような実装固有のデータ構造表現であってもよい。

> 7. Verify that the value of C.[type](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-type) is webauthn.create.

7. C.typeの値がwebauthn.createであることを確認する。

> 8. Verify that the value of C.[challenge](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge) equals the base64url encoding of options.challenge.

8. C.challengeの値がoptions.challengeのbase64urlエンコーディングと等しいことを確認する。

> 9. Verify that the value of C.[origin](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin) is an [origin](https://html.spec.whatwg.org/multipage/origin.html#concept-origin) expected by the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party). See [§ 13.4.9 Validating the origin of a credential](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin) for guidance.

9. C.origin の値が Relying Party が期待する origin であることを検証する。ガイダンスについては、第 13.4.9 節「クレデンシャルのオリジンの検証」を参照。

> 10. If C.[topOrigin](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin) is present:

10. C.topOriginが存在する場合：

> 1. Verify that the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) expects that this credential would have been created within an iframe that is not [same-origin with its ancestors](https://w3c.github.io/webappsec-credential-management/#same-origin-with-its-ancestors).

  1. Relying Party は、このクレデンシャルが祖先と同一オリジンでない iframe 内で作成され ることを期待していることを検証する。

> 2. Verify that the value of C.[topOrigin](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin) matches the [origin](https://html.spec.whatwg.org/multipage/origin.html#concept-origin) of a page that the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) expects to be sub-framed within. See [§ 13.4.9 Validating the origin of a credential](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin) for guidance.

  2. C.topOrigin の値が、Relying Party がサブフレーム化されることを期待するページのオリジン と一致することを検証する。ガイダンスについては、セ クション 13.4.9 クレデンシャルのオリジンの検証を参照のこと。

> 11. Let hash be the result of computing a hash over response.[clientDataJSON](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson) using SHA-256.

11. response.clientDataJSONをSHA-256でハッシュ計算した結果をhashとする。

> 12. Perform CBOR decoding on the [attestationObject](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-attestationobject) field of the [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse) structure to obtain the attestation statement format fmt, the [authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data) authData, and the attestation statement attStmt.

12. AuthenticatorAttestationResponse 構造体の attestationObject フィールドで CBOR デコードを実行し、認証文フォー マット fmt、認証データ authData、認証文 attStmt を取得する。

> 13. Verify that the [rpIdHash](https://www.w3.org/TR/webauthn-3/#authdata-rpidhash) in authData is the SHA-256 hash of the [RP ID](https://www.w3.org/TR/webauthn-3/#rp-id) expected by the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party).

13.  authDataのrpIdHashが、Relying Party が期待するRP IDのSHA-256ハッシュであることを確認する。

> 14. Verify that the [UP](https://www.w3.org/TR/webauthn-3/#authdata-flags-up) bit of the [flags](https://www.w3.org/TR/webauthn-3/#authdata-flags) in authData is set.

14. authDataのフラグのUPビットが設定されていることを確認する。

> 15. If the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) requires [user verification](https://www.w3.org/TR/webauthn-3/#user-verification) for this registration, verify that the [UV](https://www.w3.org/TR/webauthn-3/#authdata-flags-uv) bit of the [flags](https://www.w3.org/TR/webauthn-3/#authdata-flags) in authData is set.

15. Relying Party がこの登録のためにユーザー検証を必要とする場合、authDataのフラグのUVビットが設定されていることを確認する。

> 16. If the [BE](https://www.w3.org/TR/webauthn-3/#authdata-flags-be) bit of the [flags](https://www.w3.org/TR/webauthn-3/#authdata-flags) in authData is not set, verify that the [BS](https://www.w3.org/TR/webauthn-3/#authdata-flags-bs) bit is not set.

16. authDataのフラグのBEビットが設定されていない場合、BSビットが設定されていな いことを確認する。

> 17. If the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) uses the credential’s [backup eligibility](https://www.w3.org/TR/webauthn-3/#backup-eligibility) to inform its user experience flows and/or policies, evaluate the [BE](https://www.w3.org/TR/webauthn-3/#authdata-flags-be) bit of the [flags](https://www.w3.org/TR/webauthn-3/#authdata-flags) in authData.

17. Relying Party がクレデンシャルのバックアップ資格を使用してユーザ・エクスペリエン ス・フローおよび/またはポリシーを通知する場合は、authData 内のフラグの BE ビットを評価する。

> 18. If the Relying Party uses the credential’s backup state to inform its user experience flows and/or policies, evaluate the BS bit of the flags in authData.

18. Relying Party がクレデンシャルのバックアップ状態を使用してユーザー・エクスペリエン ス・フローおよび/またはポリシーを通知する場合は、authData 内のフラグの BS ビットを評価する。

> 19. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.

19. authData のクレデンシャル公開鍵の「alg」パラメータが、options.pubKeyCredParams.c の項目のいずれかの alg 属性と一致することを確認する。

> 20. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.

20. clientExtensionResultsのクライアント拡張出力とauthDataの拡張の認証機拡張出力の 値が、options.extensionsで指定されたクライアント拡張入力値と、options.extensionsの 一部として指定されなかった未承諾拡張(unsolicited extensions)に関する Relying Party の特定のポリシーとを考慮して、期待通りであることを検証する。一般的な場合、"are as expected "の意味は、Relying Party とどの拡張が使用されているかに固有である。

> NOTE: Client platforms MAY enact local policy that sets additional authenticator extensions or client extensions and thus cause values to appear in the authenticator extension outputs or client extension outputs that were not originally specified as part of options.extensions. Relying Parties MUST be prepared to handle such situations, whether it be to ignore the unsolicited extensions or reject the attestation. The Relying Party can make this decision based on local policy and the extensions in use.

注意: クライアントプラットフォームは、追加の認証機能拡張またはクライアント機 能拡張を設定するローカルポリシーを制定してもよい[MAY]。その結果、options.extensions の一部として元々指定されていなかった値が、認証機能拡張出力またはク ライアント機能拡張出力に現れることになる。Relying当事者は、要求されていない拡張を無視するか、あるいは認証を拒否するか、 そのような状況に対処できるように準備しなければならない[MUST]。Relying Party は、ローカルポリシーと使用中の拡張に基づいてこの決定を下すことができる。

> NOTE: Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST also be prepared to handle cases where none or not all of the requested extensions were acted upon.

注: すべての拡張はクライアントと認証者の両方にとってOPTIONALであるため、 Relying Party は、要求された拡張のどれにも対応しないか、あるいは対応し ない場合にも対応できるように準備しなければならない[MUST]。

> NOTE: The devicePubKey extension has explicit verification procedures, see § 10.2.2.3.1 Registration (create()).

注：devicePubKey 拡張には、§10.2.2.3.1 登録(create())を参照した明示的な検証手順がある。

> 21. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].

21. fmtをUSASCIIの大文字小文字を区別して、サポートされているWebAuthn認証文フォーマット識別子値と照合することで、認証文フォーマットを決定する。登録されているWebAuthn Attestation Statement Format Identifier値の最新リストは、 [RFC8809]で確立されたIANAの "WebAuthn Attestation Statement Format Identifiers "レジストリ[IANA-WebAuthn-Registries]で管理されている。

> 22. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.

22. attStmt、authData、hashが指定された認証文フォーマットfmtの検証手順を使用して、 attStmtが正しい認証文であり、有効な認証署名を伝達することを検証する。

> NOTE: Each attestation statement format specifies its own verification procedure. See § 8 Defined Attestation Statement Formats for the initially-defined formats, and [IANA-WebAuthn-Registries] for the up-to-date list.

注：各証明書書式は、それ自身の検証手順を規定する。最初に定義された書式については§8 定義された証明書の書式を、最新の一覧については[IANA-WebAuthn-Registry]を参照のこと。

> 23. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.

23. 検証に成功した場合、信頼できる情報源またはポリシーから、その認証タイプおよび認証文形式 fmt に対して許容可能なトラストアンカー（すなわち認証ルート証明書）のリストを取得する。たとえば、FIDOメタデータサービス[FIDOMetadataService]は、authDataのattestedCredentialDataのaaguidを使用して、そのような情報を取得する1つの方法を提供する。

> 24. Assess the attestation trustworthiness using the outputs of the verification procedure in step 21, as follows:

24. ステップ 21 の検証手順の出力を用いて、以下のように証明信頼度を評価する：

> - If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.

  - 証明書が提供されなかった場合は、Relying Party のポリシーに基づき、証明書が提供されな いことが許容されることを確認する。

> - If self attestation was used, verify that self attestation is acceptable under Relying Party policy.

  - 自己証明書を使用した場合は、自己証明書が Relying Party のポリシーに基づき受諾可能であることを確認する。

> - Otherwise, use the X.509 certificates returned as the attestation trust path from the verification procedure to verify that the attestation public key either correctly chains up to an acceptable root certificate, or is itself an acceptable certificate (i.e., it and the root certificate obtained in Step 22 may be the same).

  - そうでない場合は、検証手順から証明書トラスト・パスとして返された X.509 証明書を使用し、証明書公開 鍵が、許容されるルート証明書に正しくチェーンアップされているか、またはそれ自体が許容される証明 書である（すなわち、ステップ 22 で取得したルート証明書と同一である可能性がある）ことを検証する。

> 25. Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.

25. クレデンシャル ID が 1023 バイト以下であることを確認する。このバイト数より大きいクレデンシャル ID は、RP がこの登録セレモニーに失敗する原因になるべきである[SHOULD]。

> 26. Verify that the credentialId is not yet registered for any user. If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.

26. credentialId がまだどのユーザにも登録されていないことを検証する。credentialId がすでに既知の場合、Relying Party はこの登録セレモニーに失敗すべきである。

> NOTE: The rationale for Relying Parties rejecting duplicate credential IDs is as follows: credential IDs contain sufficient entropy that accidental duplication is very unlikely. However, attestation types other than self attestation do not include a self-signature to explicitly prove possession of the credential private key at registration time. Thus an attacker who has managed to obtain a user’s credential ID and credential public key for a site (this could be potentially accomplished in various ways), could attempt to register a victim’s credential as their own at that site. If the Relying Party accepts this new registration and replaces the victim’s existing credential registration, and the credentials are discoverable, then the victim could be forced to sign into the attacker’s account at their next attempt. Data saved to the site by the victim in that state would then be available to the attacker.

注：Relying Party がクレデンシャル ID の重複を拒否する根拠は以下のとおりである。クレデンシャル ID には十分なエントロピーが含まれているため、偶発的な重複は非常に考えにくい。しかし、自己認証以外の認証タイプには、登録時にクレデンシャル・プライベート鍵の所有 を明示的に証明する自己署名が含まれていない。したがって、あるサイトのユーザーのクレデンシャル ID およびクレデンシャル公開鍵を何とかして入手した攻撃者（これはさまざまな方法で達成できる可能性がある）は、被害者のクレデンシャルをそのサイトで自分のものとして登録しようとすることができる。Relying Party がこの新しい登録を受け入れ、被害者の既存のクレデンシャル登録を置き換え、クレデンシャル が発見可能である場合、被害者は次の試みで攻撃者のアカウントにサインインすることを強制される可能性が ある。その状態で被害者がサイトに保存したデータは、攻撃者が利用できるようになる。

> 27. If the attestation statement attStmt verified successfully and is found to be trustworthy, then create and store a new credential record in the user account that was denoted in options.user, with the following contents:

27. 認証文attStmtが正常に検証され、信頼できることが判明した場合、options.userで指定されたユーザアカウントに、以下の内容で新しいクレデンシャルレコードを作成し、格納する：

> 28. If the attestation statement attStmt successfully verified but is not trustworthy per step 23 above, the Relying Party SHOULD fail the registration ceremony.

28. 証明書 attStmt が正常に検証されたが、上記のステップ23に従って信頼できない場合、 Relying Party は登録セレモニーに失敗すべきである[SHOULD]。

> NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see § 6.5.4 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.

注：ただしポリシーで許可されている場合、Relying Party はクレデンシャル ID とクレデンシャル公開 鍵を登録してもよいが、クレデンシャルを自己認証のものとして扱ってもよい（§6.5.4 認証タイプ参照）。そうする場合、Relying Party は、公開鍵クレデンシャルが特定の認証子モデルによって生成された という暗号学的証明がないことを主張することになる。より詳細な議論については、[FIDOSecRef]および[UAFProtocol]を参照のこと。

> Verification of attestation objects requires that the Relying Party has a trusted method of determining acceptable trust anchors in step 22 above. Also, if certificates are being used, the Relying Party MUST have access to certificate status information for the intermediate CA certificates. The Relying Party MUST also be able to build the attestation certificate chain if the client did not provide this chain in the attestation information.

証明書オブジェクトの検証は、Relying Party が上記のステップ22において、許容可能なトラストアンカー を決定する信頼できる方法を有していることを必要とする。また、証明書が使用されている場合、Relying Party は、中間 CA 証明書の証明書ステータ ス情報にアクセスできなければならない。クライアントが証明書情報において証明書チェーンを提供していない場合、Relying Party は、証明書チェーンを構築することもできなければならない。

## [RFC 8949 Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949.html)

### [2. CBOR Data Models](https://www.rfc-editor.org/rfc/rfc8949.html#name-cbor-data-models)

> CBOR is explicit about its generic data model, which defines the set of all data items that can be represented in CBOR. Its basic generic data model is extensible by the registration of "simple values" and tags. Applications can then create a subset of the resulting extended generic data model to build their specific data models.

CBORは、CBORで表現できるすべてのデータ項目の集合を定義するジェネリック・データ・モデルを明示している。その基本的なジェネリック・データ・モデルは、「単純な値」とタグの登録によって拡張可能である。そして、アプリケーションはその結果として拡張されたジェネリック・データ・モデルのサブセットを作成し、特定のデータ・モデルを構築することができる。

> Within environments that can represent the data items in the generic data model, generic CBOR encoders and decoders can be implemented (which usually involves defining additional implementation data types for those data items that do not already have a natural representation in the environment). The ability to provide generic encoders and decoders is an explicit design goal of CBOR; however, many applications will provide their own application-specific encoders and/or decoders.

ジェネリック・データ・モデルのデータ項目を表現できる環境内では、ジェネリックなCBORエンコーダーとデコーダーを実装することができる（通常、環境内に自然な表現がまだないデータ項目については、追加の実装データタイプを定義する必要がある）。ジェネリック・エンコーダーとデコーダーを提供する能力はCBORの明確な設計目標であるが、多くのアプリケーションはアプリケーション固有のエンコーダーやデコーダーを提供するだろう。

> In the basic (unextended) generic data model defined in [Section 3](https://www.rfc-editor.org/rfc/rfc8949.html#encoding), a data item is one of the following:

セクション3で定義された基本的な（拡張されていない）汎用データモデルでは、データ項目は以下のいずれかである：

> - an integer in the range $-2^{64}..2^{64}-1$ inclusive

$-2^{64}..2^{64}-1$ の範囲の整数。

> - a simple value, identified by a number between 0 and 255, but distinct from that number itself

0から255の間の数値で識別されるが、数値そのものとは異なる単純な値。

> - a floating-point value, distinct from an integer, out of the set representable by IEEE 754 binary64 (including non-finites) [[IEEE754](https://www.rfc-editor.org/rfc/rfc8949.html#IEEE754)]

IEEE 754 binary64 [IEEE754]で表現可能な浮動小数点値（非整数を含む）のうち、整数とは異なる浮動小数点値。

> - a sequence of zero or more bytes ("byte string")

0バイト以上のバイト列（「バイト列」）。

> - a sequence of zero or more Unicode code points ("text string")

ゼロ個以上の Unicode コードポイントの並び（「テキスト文字列」）。

> - a sequence of zero or more data items ("array")

0個以上のデータ項目の並び（「配列」）。

> - a mapping (mathematical function) from zero or more data items ("keys") each to a data item ("values"), ("map")

ゼロ個以上のデータ項目（「キー」）からデータ項目（「値」）へのマッピング（数学関数）、（「マップ」）。

> - a tagged data item ("tag"), comprising a tag number (an integer in the range $0..2^{64}-1$) and the tag content (a data item)

タグ番号($0..2^{64}-1$の範囲の整数)とタグの内容(データ項目)からなるタグ付きデータ項目(「タグ」)

> Note that integer and floating-point values are distinct in this model, even if they have the same numeric value.

整数値と浮動小数点値は、たとえ同じ数値であっても、このモデルでは区別されることに注意。

> Also note that serialization variants are not visible at the generic data model level. This deliberate absence of visibility includes the number of bytes of the encoded floating-point value. It also includes the choice of encoding for an "argument" (see [Section 3](https://www.rfc-editor.org/rfc/rfc8949.html#encoding)) such as the encoding for an integer, the encoding for the length of a text or byte string, the encoding for the number of elements in an array or pairs in a map, or the encoding for a tag number.

また、直列化バリアントはジェネリック・データ・モデル・レベルでは見えないことに注意。この意図的な可視性の欠如には、エンコードされた浮動小数点値のバイト数も含まれます。また、整数のエンコーディング、テキストやバイト列の長さのエンコーディング、マップの配列やペアの要素数のエンコーディング、タグ番号のエンコーディングなど、"引数"（セクション3参照）のエンコーディングの選択も含まれます。

#### [2.1. Extended Generic Data Models](https://www.rfc-editor.org/rfc/rfc8949.html#name-extended-generic-data-model)

> This basic generic data model has been extended in this document by the registration of a number of simple values and tag numbers, such as:

この基本的なジェネリック・データ・モデルは、本文書では以下のような単純な値やタグ番号の登録によって拡張されている：

> - false, true, null, and undefined (simple values identified by 20..23, [Section 3.3](https://www.rfc-editor.org/rfc/rfc8949.html#fpnocont))

false、true、null、undefined（20～23で識別される単純な値、セクション3.3）

> integer and floating-point values with a larger range and precision than the above (tag numbers 2 to 5, [Section 3.4](https://www.rfc-editor.org/rfc/rfc8949.html#tags))

上記よりも大きな範囲と精度を持つ整数値および浮動小数点値（タグ番号2～5、セクション3.4）

> application data types such as a point in time or date/time string defined in RFC 3339 (tag numbers 1 and 0, [Section 3.4](https://www.rfc-editor.org/rfc/rfc8949.html#tags))

RFC 3339（タグ番号1および0、セクション3.4）で定義されているポイントインタイムや日付/時刻文字列などのアプリケーションデータ型

> Additional elements of the extended generic data model can be (and have been) defined via the IANA registries created for CBOR. Even if such an extension is unknown to a generic encoder or decoder, data items using that extension can be passed to or from the application by representing them at the application interface within the basic generic data model, i.e., as generic simple values or generic tags.

拡張ジェネリックデータモデルの追加要素は、CBORのために作成されたIANAレジストリを介して定義することができる（されている）。そのような拡張がジェネリックエンコーダまたはデコーダにとって未知であっても、その拡張を使用するデータ項目は、基本ジェネリックデータモデル内のアプリケーションインターフェースで表現することによって、すなわち、ジェネリック単純値またはジェネリックタグとして、アプリケーションとの間で受け渡しすることができる。

- [Concise Binary Object Representation (CBOR) Simple Values](https://www.iana.org/assignments/cbor-simple-values/cbor-simple-values.xhtml)
- [Concise Binary Object Representation (CBOR) Tags](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml)
- [CBOR Object Signing and Encryption (COSE)](https://www.iana.org/assignments/cose/cose.xhtml)

> In other words, the basic generic data model is stable as defined in this document, while the extended generic data model expands by the registration of new simple values or tag numbers, but never shrinks.

言い換えれば、基本的なジェネリック・データ・モデルはこの文書で定義されているように安定し、拡張されたジェネリック・データ・モデルは新しい単純な値やタグ番号の登録によって拡張するが、縮小することはない。

> While there is a strong expectation that generic encoders and decoders can represent false, true, and null (undefined is intentionally omitted) in the form appropriate for their programming environment, the implementation of the data model extensions created by tags is truly optional and a matter of implementation quality.

一般的なエンコーダとデコーダは、そのプログラミング環境に適した形でfalse、true、null（undefinedは意図的に省略されている）を表現できることが強く期待されているが、タグによって作成されるデータモデル拡張の実装は本当にオプションであり、実装の質の問題である。

#### [2.2. Specific Data Models](https://www.rfc-editor.org/rfc/rfc8949.html#name-specific-data-models)

> The specific data model for a CBOR-based protocol usually takes a subset of the extended generic data model and assigns application semantics to the data items within this subset and its components. When documenting such specific data models and specifying the types of data items, it is preferable to identify the types by their generic data model names ("negative integer", "array") instead of referring to aspects of their CBOR representation ("major type 1", "major type 4").

CBORベースのプロトコルの特定のデータモデルは通常、拡張された汎用データモデルのサブセットを取り、このサブセット内のデータ項目とその構成要素にアプリケーションのセマンティクスを割り当てる。このような特定のデータモデルを文書化し、データ項目の型を指定する場合、CBOR表現の側面（"major type 1"、"major type 4"）に言及するのではなく、その汎用データモデル名（"negative integer"、"array"）によって型を特定することが望ましい。

> Specific data models can also specify value equivalency (including values of different types) for the purposes of map keys and encoder freedom. For example, in the generic data model, a valid map MAY have both 0 and 0.0 as keys, and an encoder MUST NOT encode 0.0 as an integer (major type 0, [Section 3.1](https://www.rfc-editor.org/rfc/rfc8949.html#majortypes)). However, if a specific data model declares that floating-point and integer representations of integral values are equivalent, using both map keys 0 and 0.0 in a single map would be considered duplicates, even while encoded as different major types, and so invalid; and an encoder could encode integral-valued floats as integers or vice versa, perhaps to save encoded bytes.

特定のデータモデルでは、マップのキーとエンコーダの自由のために、値の等価性（異なる型の値を含む）を指定することもできる。例えば、一般的なデータモデルでは、有効なマップは0と0.0の両方をキーとして持ってもよく（MAY）、エンコーダは0.0を整数（メジャータイプ0、セクション3.1）としてエンコードしてはならない（MUST NOT）。しかし、もし特定のデータモデルが整数値の浮動小数点表現と整数表現が等価であると宣言している場合、1つのマップでマップキー0と0.0の両方を使用することは、異なるメジャータイプとしてエンコードされていても重複とみなされ、無効となる。

### [3. Specification of the CBOR Encoding](https://www.rfc-editor.org/rfc/rfc8949.html#name-specification-of-the-cbor-e)

> A CBOR data item ([Section 2](https://www.rfc-editor.org/rfc/rfc8949.html#cbor-data-models)) is encoded to or decoded from a byte string carrying a well-formed encoded data item as described in this section. The encoding is summarized in [Table 7](https://www.rfc-editor.org/rfc/rfc8949.html#jumptable) in [Appendix B](https://www.rfc-editor.org/rfc/rfc8949.html#jump-table), indexed by the initial byte. An encoder MUST produce only well-formed encoded data items. A decoder MUST NOT return a decoded data item when it encounters input that is not a well-formed encoded CBOR data item (this does not detract from the usefulness of diagnostic and recovery tools that might make available some information from a damaged encoded CBOR data item).

CBORデータ項目(セクション2)は、このセクションで説明されるように、整形式エンコードされたデータ項目を持つバイト列にエンコードされるか、またはバイト列からデコードされる。エンコーディングは付録Bの表7にまとめられ、最初のバイトでインデックスが付けられている。エンコーダーは整形式にエンコードされたデータアイテムだけを生成しな ければならない[MUST]。デコーダは、正しくエンコードされたCBORデータアイテムでない入力に出会ったとき、デコードされたデータアイテムを返してはならない(MUST NOT)(これは、破損したエンコードされたCBORデータアイテムからいくつかの情報を利用できるかもしれない診断ツールやリカバリツールの有用性を損なうものではない)。

> The initial byte of each encoded data item contains both information about the major type (the high-order 3 bits, described in [Section 3.1](https://www.rfc-editor.org/rfc/rfc8949.html#majortypes)) and additional information (the low-order 5 bits). With a few exceptions, the additional information's value describes how to load an unsigned integer "argument":

エンコードされた各データ項目の先頭バイトには、メジャー・タイプに関する情報（セクション3.1で説明する上位3ビット）と付加情報（下位5ビット）の両方が含まれる。いくつかの例外を除き、付加情報の値には符号なし整数の「引数」をロードする方法が記述されている：

> Less than 24: The argument's value is the value of the additional information.

24未満：引数の値が追加情報の値となる。

> 24, 25, 26, or 27: The argument's value is held in the following 1, 2, 4, or 8 bytes, respectively, in network byte order. For major type 7 and additional information value 25, 26, 27, these bytes are not used as an integer argument, but as a floating-point value (see [Section 3.3](https://www.rfc-editor.org/rfc/rfc8949.html#fpnocont)).

24、25、26、または27：引数の値は、ネットワーク・バイト順で、それぞれ以下の1、2、4、8バイトに保持される。メジャー・タイプ 7 および付加情報値 25、26、27 の場合、これらのバイトは整数引数としてではなく、浮動小数点値として使用される（セクション 3.3 を参照）。

> 28, 29, 30: These values are reserved for future additions to the CBOR format. In the present version of CBOR, the encoded item is not well-formed.

28, 29, 30: これらの値は将来のCBORフォーマットへの追加のために予約されている。現在のバージョンのCBORでは、符号化された項目は整形式ではない。

> 31: No argument value is derived. If the major type is 0, 1, or 6, the encoded item is not well-formed. For major types 2 to 5, the item's length is indefinite, and for major type 7, the byte does not constitute a data item at all but terminates an indefinite-length item; all are described in [Section 3.2](https://www.rfc-editor.org/rfc/rfc8949.html#indefinite).

31：引数値が導出されない。メジャータイプが0、1、6の場合、符号化された項目は整形式ではない。メジャータイプ 2 から 5 の場合、項目の長さは不定であり、メジャータイプ 7 の場合、バイトはデータ項目を全く構成せず、不定長の項目を終了する。

> The initial byte and any additional bytes consumed to construct the argument are collectively referred to as the head of the data item.

最初のバイトと、引数を構成するために消費される追加のバイトは、まとめてデータ項目の先頭と呼ばれる。

> The meaning of this argument depends on the major type. For example, in major type 0, the argument is the value of the data item itself (and in major type 1, the value of the data item is computed from the argument); in major type 2 and 3, it gives the length of the string data in bytes that follow; and in major types 4 and 5, it is used to determine the number of data items enclosed.

この引数の意味は、メジャー・タイプによって異なる。例えば、メジャー・タイプ0では、この引数はデータ項目の値そのものであり（メジャー・タイプ1では、データ項目の値は引数から計算される）、メジャー・タイプ2および3では、それに続く文字列データのバイト長を与え、メジャー・タイプ4および5では、囲まれているデータ項目の数を決定するために使用される。

> If the encoded sequence of bytes ends before the end of a data item, that item is not well-formed. If the encoded sequence of bytes still has bytes remaining after the outermost encoded item is decoded, that encoding is not a single well-formed CBOR item. Depending on the application, the decoder may either treat the encoding as not well-formed or just identify the start of the remaining bytes to the application.

エンコードされたバイト列がデータアイテムの終端より前に終わっている場合、そのアイテムは整形式ではない。エンコードされたバイト列が、最も外側のエンコードされたアイテムがデコードされた後にまだバイトが残っている場合、そのエンコードは単一の整形式CBORアイテムではない。アプリケーションによっては、デコーダはそのエンコードを整形式でないものとして扱うか、あるいは単に残りのバイトの開始をアプリケーションに識別させるかもしれない。

> A CBOR decoder implementation can be based on a jump table with all 256 defined values for the initial byte ([Table 7](https://www.rfc-editor.org/rfc/rfc8949.html#jumptable)). A decoder in a constrained implementation can instead use the structure of the initial byte and following bytes for more compact code (see [Appendix C](https://www.rfc-editor.org/rfc/rfc8949.html#pseudocode) for a rough impression of how this could look).

CBORデコーダの実装は、初期バイトに256の定義値を持つジャンプテーブルを使用することができる（表7）。制約のある実装のデコーダは、よりコンパクトなコードのために、代わりに初期バイトとそれに続くバイトの構造を使用することができる（これがどのように見えるかの大まかな印象については付録Cを参照）。

## [RFC 9052 CBOR Object Signing and Encryption (COSE): Structures and Process](https://www.rfc-editor.org/rfc/rfc9052.html)

#### [1.4. CDDL Grammar for CBOR Data Structures](https://www.rfc-editor.org/rfc/rfc9052.html#name-cddl-grammar-for-cbor-data-)

> When COSE was originally written, the Concise Data Definition Language (CDDL) [RFC8610] had not yet been published in an RFC, so it could not be used as the data description language to normatively describe the CBOR data structures employed by COSE. For that reason, the CBOR data objects defined here are described in prose. Additional (non-normative) descriptions of the COSE data objects are provided in a subset of CDDL, described below.

### [COSE Keys](https://www.rfc-editor.org/rfc/rfc9052.html#name-key-objects)

> A COSE Key structure is built on a CBOR map. The set of common parameters that can appear in a COSE Key can be found in the IANA "COSE Key Common Parameters" registry [COSE.KeyParameters](https://www.iana.org/assignments/cose/) (see Section 11.2). Additional parameters defined for specific key types can be found in the IANA "COSE Key Type Parameters" registry [COSE.KeyTypes](https://www.iana.org/assignments/cose/).

COSE キー構造は CBOR マップ上に構築される。COSE Key に現れる共通パラメータのセットは、IANA の "COSE Key Common Parameters" レジストリ [COSE.KeyParameters] にあります（セクション 11.2 を参照）。特定のキータイプ用に定義された追加のパラメータは、IANA の「COSE Key Type Parameters」レジストリ [COSE.KeyTypes]にあります。

> A COSE Key Set uses a CBOR array object as its underlying type. The values of the array elements are COSE Keys. A COSE Key Set MUST have at least one element in the array. Examples of COSE Key Sets can be found in [Appendix C.7](https://datatracker.ietf.org/doc/html/rfc9052#COSE_KEYS).

COSE キーセットは、その基礎となる型として CBOR 配列オブジェクトを使用します。配列要素の値は COSE キーである。COSE キーセットは、配列に少なくとも 1 つの要素を持たなければならない（MUST）。COSE キーセットの例は、付録 C.7.¶ に記載されている。

> Each element in a COSE Key Set MUST be processed independently. If one element in a COSE Key Set is either malformed or uses a key that is not understood by an application, that key is ignored, and the other keys are processed normally.

COSE 鍵セットの各要素は、独立して処理されなければならない（MUST）。COSE 鍵セット内の 1 つの要素が不正な形式であるか、アプリケーションに理解されない鍵を使用し ている場合、その鍵は無視され、他の鍵は正常に処理される。

> The element "kty" is a required element in a COSE_Key map.

要素 "kty" は、COSE_Key マップの必須要素です。

> The CDDL grammar describing COSE_Key and COSE_KeySet is:

COSE_Key と COSE_KeySet を記述する CDDL 文法は以下のとおりである：

```
COSE_Key = {
    1 => tstr / int,          ; kty
    ? 2 => bstr,              ; kid
    ? 3 => tstr / int,        ; alg
    ? 4 => [+ (tstr / int) ], ; key_ops
    ? 5 => bstr,              ; Base IV
    * label => values
}

COSE_KeySet = [+COSE_Key]
```

## メモ

- CBOR は [Appendix A. Examples of Encoded CBOR Data Items](https://www.rfc-editor.org/rfc/rfc8949.html#name-examples-of-encoded-cbor-da) と [Appendix B. Jump Table for Initial Byte](https://www.rfc-editor.org/rfc/rfc8949.html#name-jump-table-for-initial-byte) を見ると雰囲気分かる
