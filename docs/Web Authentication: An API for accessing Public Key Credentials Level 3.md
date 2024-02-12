# [7. WebAuthn Relying Party Operations](https://www.w3.org/TR/webauthn-3/#sctn-rp-operations)

> A registration or authentication ceremony begins with the WebAuthn Relying Party creating a PublicKeyCredentialCreationOptions or PublicKeyCredentialRequestOptions object, respectively, which encodes the parameters for the ceremony. The Relying Party SHOULD take care to not leak sensitive information during this stage; see § 14.6.2 Username Enumeration for details.

[登録](https://www.w3.org/TR/webauthn-3/#registration-ceremony)または[認証セレモニー](https://www.w3.org/TR/webauthn-3/#authentication-ceremony)は、[WebAuthn Relying Party](https://www.w3.org/TR/webauthn-3/#webauthn-relying-party) がそれぞれ [PublicKeyCredentialCreationOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions) または [PublicKeyCredentialRequestOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions) オブジェクトを作成することから始まる。詳細については [14.6.2節 Username Enumeration](https://www.w3.org/TR/webauthn-3/#sctn-username-enumeration) を参照のこと。

> Upon successful execution of create() or get(), the Relying Party's script receives a PublicKeyCredential containing an AuthenticatorAttestationResponse or AuthenticatorAssertionResponse structure, respectively, from the client. It must then deliver the contents of this structure to the Relying Party server, using methods outside the scope of this specification. This section describes the operations that the Relying Party must perform upon receipt of these structures.

[create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)または[get()](https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get)の実行に成功すると、[Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) のスクリプトは、それぞれ [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse) または [AuthenticatorAssertionResponse](https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse) 構造体を含む [PublicKeyCredential](https://www.w3.org/TR/webauthn-3/#publickeycredential) をクライアントから受け取る。その後、本仕様の範囲外のメソッドを使用して、この構造体のコンテンツを [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) サーバーに配信する必要がある。このセクションでは、これらの構造体を受け取ったときに [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) が実行しなけ ればならない操作について説明する。

## [7.1. Registering a New Credential](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)

> In order to perform a registration ceremony, the Relying Party MUST proceed as follows:

[登録セレモニー](https://www.w3.org/TR/webauthn-3/#registration-ceremony)を行うために、[Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party)は以下の手続きを行わなければならない：

> 1. Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.

1. optionsを、セレモニーに対する[Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party)のニーズに合わせて構成された新しい[PublicKeyCredentialCreationOptions](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions)構造体とする。

> 2. Call [navigator.credentials.create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) and pass options as the [publicKey](https://www.w3.org/TR/webauthn-3/#dom-credentialcreationoptions-publickey) option. Let credential be the result of the successfully resolved promise. If the promise is rejected, abort the ceremony with a user-visible error, or otherwise guide the user experience as might be determinable from the context available in the rejected promise. For example if the promise is rejected with an error code equivalent to "[InvalidStateError](https://webidl.spec.whatwg.org/#invalidstateerror)", the user might be instructed to use a different [authenticator](https://www.w3.org/TR/webauthn-3/#authenticator). For information on different error contexts and the circumstances leading to them, see [§ 6.3.2 The authenticatorMakeCredential Operation.](https://www.w3.org/TR/webauthn-3/#sctn-op-make-cred)

1. navigator.credentials.create()を呼び出し、publicKeyオプションとしてoptionsを渡す。resolveされたpromiseの結果をcredentialとする。promiseが拒否された場合、ユーザーから見えるエラーでセレモニーを中止するか、拒否されたpromiseで利用可能なコンテキストから判断可能なユーザーエクスペリエンスをガイドします。例えば、"InvalidStateError"と同等のエラーコードでpromiseが拒否された場合、ユーザは別の認証器を使用するように指示されるかもしれない。さまざまなエラーコンテキストとそれに至る状況については、セクション6.3.2 authenticatorMakeCredentialオペレーションを参照のこと。

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

9. C.origin の値がRelying Partyが期待する origin であることを検証する。ガイダンスについては、第 13.4.9 節「クレデンシャルのオリジンの検証」を参照。

> 10. If C.[topOrigin](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin) is present:

10. C.topOriginが存在する場合：

> 1. Verify that the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) expects that this credential would have been created within an iframe that is not [same-origin with its ancestors](https://w3c.github.io/webappsec-credential-management/#same-origin-with-its-ancestors).

  1. Relying Partyは、このクレデンシャルが祖先と同一オリジンでない iframe 内で作成され ることを期待していることを検証する。

> 2. Verify that the value of C.[topOrigin](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin) matches the [origin](https://html.spec.whatwg.org/multipage/origin.html#concept-origin) of a page that the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) expects to be sub-framed within. See [§ 13.4.9 Validating the origin of a credential](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin) for guidance.

  2. C.topOrigin の値が、Relying Partyがサブフレーム化されることを期待するページのオリジン と一致することを検証する。ガイダンスについては、セ クション 13.4.9 クレデンシャルのオリジンの検証を参照のこと。

> 11. Let hash be the result of computing a hash over response.[clientDataJSON](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson) using SHA-256.

11. response.clientDataJSONをSHA-256でハッシュ計算した結果をhashとする。

> 12. Perform CBOR decoding on the [attestationObject](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-attestationobject) field of the [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse) structure to obtain the attestation statement format fmt, the [authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data) authData, and the attestation statement attStmt.

12. AuthenticatorAttestationResponse 構造体の attestationObject フィールドで CBOR デコードを実行し、認証文フォー マット fmt、認証データ authData、認証文 attStmt を取得する。

> 13. Verify that the [rpIdHash](https://www.w3.org/TR/webauthn-3/#authdata-rpidhash) in authData is the SHA-256 hash of the [RP ID](https://www.w3.org/TR/webauthn-3/#rp-id) expected by the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party).

13.  authDataのrpIdHashが、Relying Partyが期待するRP IDのSHA-256ハッシュであることを確認する。

> 14. Verify that the [UP](https://www.w3.org/TR/webauthn-3/#authdata-flags-up) bit of the [flags](https://www.w3.org/TR/webauthn-3/#authdata-flags) in authData is set.

14. authDataのフラグのUPビットが設定されていることを確認する。

> 15. If the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) requires [user verification](https://www.w3.org/TR/webauthn-3/#user-verification) for this registration, verify that the [UV](https://www.w3.org/TR/webauthn-3/#authdata-flags-uv) bit of the [flags](https://www.w3.org/TR/webauthn-3/#authdata-flags) in authData is set.

15. Relying Partyがこの登録のためにユーザー検証を必要とする場合、authDataのフラグのUVビットが設定されていることを確認する。

> 16. If the [BE](https://www.w3.org/TR/webauthn-3/#authdata-flags-be) bit of the [flags](https://www.w3.org/TR/webauthn-3/#authdata-flags) in authData is not set, verify that the [BS](https://www.w3.org/TR/webauthn-3/#authdata-flags-bs) bit is not set.

16. authDataのフラグのBEビットが設定されていない場合、BSビットが設定されていな いことを確認する。

> 17. If the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party) uses the credential’s [backup eligibility](https://www.w3.org/TR/webauthn-3/#backup-eligibility) to inform its user experience flows and/or policies, evaluate the [BE](https://www.w3.org/TR/webauthn-3/#authdata-flags-be) bit of the [flags](https://www.w3.org/TR/webauthn-3/#authdata-flags) in authData.

17. Relying Partyがクレデンシャルのバックアップ資格を使用してユーザ・エクスペリエン ス・フローおよび/またはポリシーを通知する場合は、authData 内のフラグの BE ビットを評価する。

> 18. If the Relying Party uses the credential’s backup state to inform its user experience flows and/or policies, evaluate the BS bit of the flags in authData.

18. Relying Party がクレデンシャルのバックアップ状態を使用してユーザー・エクスペリエン ス・フローおよび/またはポリシーを通知する場合は、authData 内のフラグの BS ビットを評価する。

> 19. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.

19. authData のクレデンシャル公開鍵の「alg」パラメータが、options.pubKeyCredParams.c の項目のいずれかの alg 属性と一致することを確認する。

> 20. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.

20. clientExtensionResultsのクライアント拡張出力とauthDataの拡張の認証機拡張出力の 値が、options.extensionsで指定されたクライアント拡張入力値と、options.extensionsの 一部として指定されなかった未承諾拡張(unsolicited extensions)に関するRelying Partyの特定のポリシーとを考慮して、期待通りであることを検証する。一般的な場合、"are as expected "の意味は、Relying Partyとどの拡張が使用されているかに固有である。

> NOTE: Client platforms MAY enact local policy that sets additional authenticator extensions or client extensions and thus cause values to appear in the authenticator extension outputs or client extension outputs that were not originally specified as part of options.extensions. Relying Parties MUST be prepared to handle such situations, whether it be to ignore the unsolicited extensions or reject the attestation. The Relying Party can make this decision based on local policy and the extensions in use.

注意: クライアントプラットフォームは、追加の認証機能拡張またはクライアント機 能拡張を設定するローカルポリシーを制定してもよい[MAY]。その結果、options.extensions の一部として元々指定されていなかった値が、認証機能拡張出力またはク ライアント機能拡張出力に現れることになる。Relying当事者は、要求されていない拡張を無視するか、あるいは認証を拒否するか、 そのような状況に対処できるように準備しなければならない[MUST]。Relying Partyは、ローカルポリシーと使用中の拡張に基づいてこの決定を下すことができる。

> NOTE: Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST also be prepared to handle cases where none or not all of the requested extensions were acted upon.

注: すべての拡張はクライアントと認証者の両方にとってOPTIONALであるため、 Relying Partyは、要求された拡張のどれにも対応しないか、あるいは対応し ない場合にも対応できるように準備しなければならない[MUST]。

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

注：依拠当事者がクレデンシャル ID の重複を拒否する根拠は以下のとおりである。クレデンシャル ID には十分なエントロピーが含まれているため、偶発的な重複は非常に考えにくい。しかし、自己認証以外の認証タイプには、登録時にクレデンシャル・プライベート鍵の所有 を明示的に証明する自己署名が含まれていない。したがって、あるサイトのユーザーのクレデンシャル ID およびクレデンシャル公開鍵を何とかして入手した攻撃者（これはさまざまな方法で達成できる可能性がある）は、被害者のクレデンシャルをそのサイトで自分のものとして登録しようとすることができる。Relying Party がこの新しい登録を受け入れ、被害者の既存のクレデンシャル登録を置き換え、クレデンシャル が発見可能である場合、被害者は次の試みで攻撃者のアカウントにサインインすることを強制される可能性が ある。その状態で被害者がサイトに保存したデータは、攻撃者が利用できるようになる。

> 27. If the attestation statement attStmt verified successfully and is found to be trustworthy, then create and store a new credential record in the user account that was denoted in options.user, with the following contents:

27. 認証文attStmtが正常に検証され、信頼できることが判明した場合、options.userで指定されたユーザアカウントに、以下の内容で新しいクレデンシャルレコードを作成し、格納する：

> 28. If the attestation statement attStmt successfully verified but is not trustworthy per step 23 above, the Relying Party SHOULD fail the registration ceremony.

28. 証明書 attStmt が正常に検証されたが、上記のステップ23に従って信頼できない場合、 Relying Party は登録セレモニーに失敗すべきである[SHOULD]。

> NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see § 6.5.4 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.

注：ただしポリシーで許可されている場合、依拠当事者はクレデンシャル ID とクレデンシャル公開 鍵を登録してもよいが、クレデンシャルを自己認証のものとして扱ってもよい（§6.5.4 認証タイプ参照）。そうする場合、依拠当事者は、公開鍵クレデンシャルが特定の認証子モデルによって生成された という暗号学的証明がないことを主張することになる。より詳細な議論については、[FIDOSecRef]および[UAFProtocol]を参照のこと。

> Verification of attestation objects requires that the Relying Party has a trusted method of determining acceptable trust anchors in step 22 above. Also, if certificates are being used, the Relying Party MUST have access to certificate status information for the intermediate CA certificates. The Relying Party MUST also be able to build the attestation certificate chain if the client did not provide this chain in the attestation information.

証明書オブジェクトの検証は、信頼当事者が上記のステップ22において、許容可能なトラストアンカー を決定する信頼できる方法を有していることを必要とする。また、証明書が使用されている場合、依拠当事者は、中間 CA 証明書の証明書ステータ ス情報にアクセスできなければならない。クライアントが証明書情報において証明書チェーンを提供していない場合、依拠当事者は、証明 書チェーンを構築することもできなければならない。
