package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"example.com/db"
	"example.com/model"
	"example.com/model/cose"
	"github.com/fxamacker/cbor/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

type Status struct {
	Message string
}

type RegisterStartMessage struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
}

func handleRegisterStart(c echo.Context) error {
	registerStartMessage := new(RegisterStartMessage)
	if err := c.Bind(registerStartMessage); err != nil {
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	user, ok := db.GetUser(registerStartMessage.Name)
	if !ok {
		user = model.User{
			Id:          make([]byte, 16),
			Name:        registerStartMessage.Name,
			DisplayName: registerStartMessage.DisplayName,
		}
		db.SaveUser(user)
		log.Infof("generate User. Id: %v, Name: %v", hex.EncodeToString(user.Id), user.Name)
	}

	// 1. Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.
	options, err := model.NewPublicKeyCredentialCreationOptions(user)
	if err != nil {
		c.Logger().Error("failed to NewPublicKeyCredentialCreationOptions. err: " + err.Error())
		return c.JSON(http.StatusInternalServerError, Status{Message: "error"})
	}

	db.SaveRegisterOption(options)

	c.Logger().Infof("generate challenge: %v", base64.RawURLEncoding.EncodeToString(options.Challenge))

	return c.JSON(http.StatusOK, &options)
}

type RegisterResultMessage struct {
	Id       string `json:"id"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    []byte   `json:"clientDataJSON"`
		AttestationObject []byte   `json:"attestationObject"`
		Transports        []string `json:"transports"`
	} `json:"response"`
}

func handleRegisterEnd(c echo.Context) error {
	registerMessage := new(RegisterResultMessage)
	if err := c.Bind(registerMessage); err != nil {
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 6. Let C, the [client data](https://www.w3.org/TR/webauthn-3/#client-data) claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
	var clientData model.CollectedClientData
	if err := json.Unmarshal(registerMessage.Response.ClientDataJSON, &clientData); err != nil {
		c.Logger().Errorf("error: %v, clientDataJSON: %v", err, string(registerMessage.Response.ClientDataJSON))
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 7. Verify that the value of C.[type](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-type) is webauthn.create.
	if clientData.Type != "webauthn.create" {
		c.Logger().Error("type is not valid")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 8. Verify that the value of C.[challenge](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge) equals the base64url encoding of options.challenge.
	c.Logger().Infof("receive challenge: %v", clientData.Challenge)

	options, ok := db.GetRegisterOption(clientData.Challenge)
	if !ok {
		c.Logger().Error("challenge is not valid")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}
	defer db.DeleteRegisterOption(clientData.Challenge)

	// 9. Verify that the value of C.[origin](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin) is an [origin](https://html.spec.whatwg.org/multipage/origin.html#concept-origin) expected by the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party). See [§ 13.4.9 Validating the origin of a credential](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin) for guidance.
	u, err := url.Parse(clientData.Origin)
	if err != nil {
		c.Logger().Error(err)
	}
	if options.Rp.Id != u.Hostname() {
		c.Logger().Error("origin is not valid")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 11. Let hash be the result of computing a hash over response.[clientDataJSON](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson) using SHA-256.
	// hash := sha256.Sum256(registerMessage.Response.ClientDataJSON)

	// 12. Perform CBOR decoding on the [attestationObject](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-attestationobject) field of the [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse) structure to obtain the attestation statement format fmt, the [authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data) authData, and the attestation statement attStmt.
	var attestationObject model.AttestationObject
	if err := cbor.Unmarshal(registerMessage.Response.AttestationObject, &attestationObject); err != nil {
		c.Logger().Errorf("attestationObject is not valid: %v", err)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	authData, err := model.UnmarshalAuthenticatorData(attestationObject.AuthData)
	if err != nil {
		c.Logger().Errorf("authenticatorData is not valid: %v", err)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 13. Verify that the [rpIdHash](https://www.w3.org/TR/webauthn-3/#authdata-rpidhash) in authData is the SHA-256 hash of the [RP ID](https://www.w3.org/TR/webauthn-3/#rp-id) expected by the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party).
	correctRpIdHash := sha256.Sum256([]byte(options.Rp.Id))
	if !bytes.Equal(authData.RpIdHash, correctRpIdHash[:]) {
		c.Logger().Errorf("rpIdHash is different. want: %x, got: %x", correctRpIdHash, authData.RpIdHash)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 14. Verify that the [UP](https://www.w3.org/TR/webauthn-3/#authdata-flags-up) bit of the [flags](https://www.w3.org/TR/webauthn-3/#authdata-flags) in authData is set.
	if !authData.Flags.UP {
		c.Logger().Errorf("up flag is not active")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 16. If the [BE](https://www.w3.org/TR/webauthn-3/#authdata-flags-be) bit of the [flags](https://www.w3.org/TR/webauthn-3/#authdata-flags) in authData is not set, verify that the [BS](https://www.w3.org/TR/webauthn-3/#authdata-flags-bs) bit is not set.
	if !authData.Flags.BE {
		if authData.Flags.BS {
			return c.JSON(http.StatusBadRequest, Status{Message: "error"})
		}
	}

	// 19. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
	find := false
	for _, credParams := range options.PubKeyCredParams {
		if authData.AttestedCredentialData.CredentialPublicKey.AlgType() == credParams.Alg {
			find = true
			break
		}
	}
	if !find {
		c.Logger().Errorf("alg is not valid")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 20. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
	// TODO: 拡張はいったん無視

	// 21. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
	// 一旦 attestation none 想定
	switch attestationObject.Fmt {
	case model.Packed:
	case model.Tpm:
	case model.AndroidKey:
	case model.AndroidSatetynet:
	case model.FidoU2F:
	case model.Apple:
	case model.None:
		// 何もしない
	default:
		c.Logger().Errorf("fmt is not valid")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 22. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
	switch attestationObject.Fmt {
	case model.None:
	default:
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 25. Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
	if len(authData.AttestedCredentialData.CredentialId) > 1023 {
		c.Logger().Errorf("credential Id is too long")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 26. Verify that the credentialId is not yet registered for any user. If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.
	if _, ok := db.GetUserByCredentialId(hex.EncodeToString(authData.AttestedCredentialData.CredentialId)); ok {
		c.Logger().Errorf("duplicate credential id")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 27. If the attestation statement attStmt verified successfully and is found to be trustworthy, then create and store a new credential record in the user account that was denoted in options.user, with the following contents:
	credentialRecord := model.CredentialRecord{
		Id:                    authData.AttestedCredentialData.CredentialId,
		Type:                  registerMessage.Type,
		PublicKey:             authData.AttestedCredentialData.CredentialPublicKey,
		Transports:            registerMessage.Response.Transports,
		AttestationObject:     attestationObject,
		AttestationClientData: clientData,
	}

	db.SaveCredential(options.User.Name, credentialRecord)

	return c.JSON(http.StatusAccepted, Status{Message: "accepted"})
}

type AttestationStartMessage struct {
	Name             string `json:"name"`
	UserVerification string `json:"userVerification"`
}

// 1. Let options be a new PublicKeyCredentialRequestOptions structure configured to the Relying Party's needs for the ceremony.
func handleAttestationStart(c echo.Context) error {
	attStartMessage := new(AttestationStartMessage)
	if err := c.Bind(attStartMessage); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	credentialRecords, ok := db.GetCredentialByUserName(attStartMessage.Name)
	if !ok {
		c.Logger().Errorf("user name: %v: credentialRecord not found", attStartMessage.Name)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}
	var allowCredentials []model.PublicKeyCredentialDescriptor
	for _, cr := range credentialRecords {
		allowCredentials = append(allowCredentials, model.PublicKeyCredentialDescriptor{
			Id:   cr.Id,
			Type: cr.Type,
		})
	}
	options, err := model.NewPublicKeyCredentialRequestOptions()
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, Status{Message: "error"})
	}

	challengeString := strings.TrimRight(base64.StdEncoding.EncodeToString(options.Challenge), "=")

	db.SaveAttestationOption(options)
	c.Logger().Infof("generate challenge: %v", challengeString)

	options.AllowCredentials = allowCredentials
	return c.JSON(http.StatusOK, options)
}

type AttestationEndMessage struct {
	Id       string `json:"id"`
	Response struct {
		ClientDataJSON    []byte `json:"clientDataJSON"`
		AuthenticatorData []byte `json:"authenticatorData"`
		Signature         []byte `json:"signature"`
		UserHandle        []byte `json:"userHandle,omitempty"`
	}
}

func handleAttestationEnd(c echo.Context) error {
	attestationEndMessage := new(AttestationEndMessage)
	if err := c.Bind(attestationEndMessage); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, Status{"error"})
	}

	// 11. Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.
	var clientData model.CollectedClientData
	if err := json.Unmarshal(attestationEndMessage.Response.ClientDataJSON, &clientData); err != nil {
		c.Logger().Errorf("error: %v, clientDataJSON: %v", err, string(attestationEndMessage.Response.ClientDataJSON))
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 13. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	challenge := strings.Replace(strings.Replace(clientData.Challenge, "-", "+", -1), "_", "/", -1)
	c.Logger().Infof("receive challenge: %v", challenge)

	options, ok := db.GetAttestationOption(challenge)
	if !ok {
		c.Logger().Error("challenge is not valid")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}
	db.DeleteAttestationOption(clientData.Challenge)

	// 5. If options.allowCredentials is not empty, verify that credential.id identifies one of the public key credentials listed in options.allowCredentials.
	credentialIdBase64 := strings.Replace(strings.Replace(attestationEndMessage.Id, "-", "+", -1), "_", "/", -1)
	if shortage := len(attestationEndMessage.Id) % 4; shortage != 0 {
		credentialIdBase64 += strings.Repeat("=", 4-shortage)
	}

	credentialId, err := base64.StdEncoding.DecodeString(credentialIdBase64)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	if len(options.AllowCredentials) > 0 {
		find := false
		for _, allowCredential := range options.AllowCredentials {
			if bytes.Equal(credentialId, allowCredential.Id) {
				find = true
			}
		}
		if !find {
			c.Logger().Error("credential.id is not valid")
			return c.JSON(http.StatusBadRequest, Status{Message: "error"})
		}
	}

	// 12. Verify that the value of C.type is the string webauthn.get.
	if clientData.Type != "webauthn.get" {
		c.Logger().Error("type is not valid")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 14. Verify that the value of C.origin is an origin expected by the Relying Party. See § 13.4.9 Validating the origin of a credential for guidance.
	u, err := url.Parse(clientData.Origin)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}
	if options.RpId != u.Hostname() {
		c.Logger().Error("origin is not valid")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 15. If C.topOrigin is present:
	// TODO: iframe は無視

	// 16. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	authData, err := model.UnmarshalAuthenticatorData(attestationEndMessage.Response.AuthenticatorData)
	if err != nil {
		c.Logger().Errorf("authenticatorData is not valid: %v", err)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}
	correctRpIdHash := sha256.Sum256([]byte(options.RpId))
	if !bytes.Equal(authData.RpIdHash, correctRpIdHash[:]) {
		c.Logger().Errorf("rpIdHash is different. want: %x, got: %x", correctRpIdHash, authData.RpIdHash)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 17. Verify that the UP bit of the flags in authData is set.
	if !authData.Flags.UP {
		c.Logger().Errorf("Up is not set")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 18. Determine whether user verification is required for this assertion. User verification SHOULD be required if, and only if, options.userVerification is set to required.
	// if options.UserVerification == "required" {
	// 	// ユーザの検証やる？
	// }

	// 19. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
	if !authData.Flags.BE {
		if authData.Flags.BS {
			c.Logger().Error("flag is not valid")
			return c.JSON(http.StatusBadRequest, Status{Message: "error"})
		}
	}

	// 20. If the credential backup state is used as part of Relying Party business logic or policy, let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData. Compare currentBe and currentBs with credentialRecord.backupEligible and credentialRecord.backupState:
	// Backup の状態を見て何かしたければ

	// 21. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
	// TODO: 拡張はいったん無視

	// 22. Let hash be the result of computing a hash over the cData using SHA-256.
	hash := sha256.Sum256(attestationEndMessage.Response.ClientDataJSON)

	// 23. Using credentialRecord.publicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
	credentialRecord, ok := db.GetCredential(hex.EncodeToString(credentialId))
	if !ok {
		c.Logger().Error("credentialRecord is not found")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}
	target := append(attestationEndMessage.Response.AuthenticatorData, hash[:]...)
	switch pubKey := credentialRecord.PublicKey.(type) {
	case cose.EC2PublicKey:
		if err := pubKey.Verify(target, attestationEndMessage.Response.Signature); err != nil {
			c.Logger().Error(err)
			return c.JSON(http.StatusBadRequest, Status{Message: "error"})
		}
	default:
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 24. If authData.signCount is nonzero or credentialRecord.signCount is nonzero, then run the following sub-step:
	// 一部必ず0を入れて返してくる環境が有るらしいので逆転していなければ無視
	if credentialRecord.SignCount > authData.SignCount {
		c.Logger().Errorf("invalid signCount record: %v, new: %v", credentialRecord.SignCount, authData.SignCount)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 25. If response.attestationObject is present and the Relying Party wishes to verify the attestation then perform CBOR decoding on attestationObject to obtain the attestation statement format fmt, and the attestation statement attStmt.
	// attestation: none にしちゃうのでいったん無視

	// 26. Update credentialRecord with new state values:
	newCR := model.CredentialRecord{
		Id:                    credentialRecord.Id,
		Type:                  credentialRecord.Type,
		PublicKey:             credentialRecord.PublicKey,
		SignCount:             authData.SignCount,
		Flags:                 credentialRecord.Flags, // 面倒だったのでいったんそのまま
		Transports:            credentialRecord.Transports,
		AttestationObject:     credentialRecord.AttestationObject, // front に attestationObject の型が無いのでいったんそのまま
		AttestationClientData: clientData,
	}
	if err := db.UpdateCredential(newCR); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	return c.JSON(http.StatusAccepted, Status{Message: "accepted"})
}

func main() {
	e := echo.New()

	e.Use(
		// middleware.Logger(),
		middleware.CORS(),
	)

	e.Logger.SetLevel(log.INFO)

	e.GET("/ping", func(c echo.Context) error {
		return c.JSON(http.StatusOK, &Status{Message: "pong"})
	})

	register := e.Group("register")
	register.POST("/start", handleRegisterStart)
	register.POST("/end", handleRegisterEnd)

	attestation := e.Group("attestation")
	attestation.POST("/start", handleAttestationStart)
	attestation.POST("/end", handleAttestationEnd)

	e.Logger.Fatal(e.Start(":8080"))
}
