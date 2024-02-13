package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"example.com/model"
	"example.com/webauthn"
	"github.com/fxamacker/cbor/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

type Status struct {
	Message string
}

type RegisterMessage struct {
	Response webauthn.AuthenticatorAttestationResponse `json:"response"`
	Results  any                                       `json:"results"`
}

var (
	optionsMap = make(map[string]webauthn.PublicKeyCredentialCreationOptions)
)

func handleRegisterStart(c echo.Context) error {
	// 1. Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.
	options, err := webauthn.NewPublicKeyCredentialCreationOptions(model.User{
		Id:          make([]byte, 16),
		Name:        "hoge@example.com",
		DisplayName: "okapon",
	})
	if err != nil {
		c.Logger().Error("failed to NewPublicKeyCredentialCreationOptions. err: " + err.Error())
		return c.JSON(http.StatusInternalServerError, Status{Message: "error"})
	}

	challengeB64 := base64.StdEncoding.EncodeToString(options.Challenge)

	optionsMap[challengeB64] = options

	c.Logger().Infof("generate challenge: %v", challengeB64)

	return c.JSON(http.StatusOK, &options)
}

func handleRegisterEnd(c echo.Context) error {
	registerMessage := new(RegisterMessage)
	if err := c.Bind(registerMessage); err != nil {
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 6. Let C, the [client data](https://www.w3.org/TR/webauthn-3/#client-data) claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
	var clientData webauthn.CollectedClientData
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
	options, ok := optionsMap[clientData.Challenge+"=="]
	if !ok {
		c.Logger().Error("challenge is not valid")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 9. Verify that the value of C.[origin](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin) is an [origin](https://html.spec.whatwg.org/multipage/origin.html#concept-origin) expected by the [Relying Party](https://www.w3.org/TR/webauthn-3/#relying-party). See [§ 13.4.9 Validating the origin of a credential](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin) for guidance.
	if options.Rp.Id == clientData.Origin {
		c.Logger().Error("origin is not valid")
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	// 11. Let hash be the result of computing a hash over response.[clientDataJSON](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson) using SHA-256.
	// hash := sha256.Sum256(registerMessage.Response.ClientDataJSON)

	// 12. Perform CBOR decoding on the [attestationObject](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-attestationobject) field of the [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse) structure to obtain the attestation statement format fmt, the [authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data) authData, and the attestation statement attStmt.
	// TODO: よくわからない
	var attestationObject webauthn.AttestationObject
	if err := cbor.Unmarshal(registerMessage.Response.AttestationObject, &attestationObject); err != nil {
		c.Logger().Errorf("attestationObject is not valid: %v", err)
		return c.JSON(http.StatusBadRequest, Status{Message: "error"})
	}

	authData, err := webauthn.NewAuthData(attestationObject.AuthData)
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

	return c.JSON(http.StatusAccepted, Status{Message: "accepted"})
}

func handleAttestationStart(c echo.Context) error {
	return c.JSON(http.StatusNotFound, Status{Message: "error"})
}

func handleAttestationEnd(c echo.Context) error {
	return c.JSON(http.StatusNotFound, Status{Message: "error"})
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
