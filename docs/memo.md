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

## [RFC 9052 CBOR Object Signing and Encryption (COSE): Structures and Process](https://www.rfc-editor.org/rfc/rfc9052.html)

### [COSE Keys](https://www.rfc-editor.org/rfc/rfc9052.html#name-key-objects)

> A COSE Key structure is built on a CBOR map. The set of common parameters that can appear in a COSE Key can be found in the IANA "COSE Key Common Parameters" registry [COSE.KeyParameters](https://www.iana.org/assignments/cose/) (see Section 11.2). Additional parameters defined for specific key types can be found in the IANA "COSE Key Type Parameters" registry [COSE.KeyTypes](https://www.iana.org/assignments/cose/).

COSE キー構造は CBOR マップ上に構築される。COSE Key に現れる共通パラメータのセットは、IANA の "COSE Key Common Parameters" レジストリ [COSE.KeyParameters] にあります（セクション 11.2 を参照）。特定のキータイプ用に定義された追加のパラメータは、IANA の「COSE Key Type Parameters」レジストリ [COSE.KeyTypes]にあります。

> A COSE Key Set uses a CBOR array object as its underlying type. The values of the array elements are COSE Keys. A COSE Key Set MUST have at least one element in the array. Examples of COSE Key Sets can be found in [Appendix C.7](https://datatracker.ietf.org/doc/html/rfc9052#COSE_KEYS).

COSE キーセットは、その基礎となる型として CBOR 配列オブジェクトを使用します。配列要素の値は COSE キーである。COSE キーセットは、配列に少なくとも 1 つの要素を持たなければならない（MUST）。COSE キーセットの例は、付録 C.7.¶ に記載されている。

> Each element in a COSE Key Set MUST be processed independently. If one element in a COSE Key Set is either malformed or uses a key that is not understood by an application, that key is ignored, and the other keys are processed normally.

COSE 鍵セットの各要素は、独立して処理されなければならない（MUST）。COSE 鍵セット内の 1 つの要素が不正な形式であるか、アプリケーションに理解されない鍵を使用し ている場合、その鍵は無視され、他の鍵は正常に処理される。

> The element "kty" is a required element in a COSE_Key map.

> The CDDL grammar describing COSE_Key and COSE_KeySet is:

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
