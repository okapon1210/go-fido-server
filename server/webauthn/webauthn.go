package webauthn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"example.com/model"
	"github.com/fxamacker/cbor/v2"
)

type COSEAlgorithmIdentifier int32

type PublicKeyCredentialEntity struct {
	Name string `json:"name"`
}

type PublicKeyCredentialRpEntity struct {
	PublicKeyCredentialEntity
	Id string `json:"id,omitempty"`
}

type PublicKeyCredentialUserEntity struct {
	PublicKeyCredentialEntity
	Id          []byte `json:"id"`
	DisplayName string `json:"displayName"`
}

type PublicKeyCredentialParameters struct {
	Type string                  `json:"type"`
	Alg  COSEAlgorithmIdentifier `json:"alg"`
}

type PublicKeyCredentialDescriptor struct {
	Type       string   `json:"type"`
	Id         []byte   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

type authenticatorSelectionCriteria struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
	RequireResidentKey      bool   `json:"requireResidentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
}

func NewAuthenticatorSelectionCriteria(authAtt, resiKey string, reqResiKey *bool, uv string) authenticatorSelectionCriteria {
	var rrkey bool
	if reqResiKey != nil {
		rrkey = *reqResiKey
	}
	return authenticatorSelectionCriteria{
		AuthenticatorAttachment: authAtt,
		ResidentKey:             resiKey,
		RequireResidentKey:      rrkey,
		UserVerification:        uv,
	}
}

type PublicKeyCredentialCreationOptions struct {
	Rp                     PublicKeyCredentialRpEntity     `json:"rp"`
	User                   PublicKeyCredentialUserEntity   `json:"user"`
	Challenge              []byte                          `json:"challenge"`
	PubKeyCredParams       []PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	Timeout                uint32                          `json:"timeout,omitempty"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection authenticatorSelectionCriteria  `json:"authenticatorSelection,omitempty"`
	Hints                  []string                        `json:"hints,omitempty"`
	Attestation            string                          `json:"attestation,omitempty"`
	AttestationFormats     []string                        `json:"attestationFormats,omitempty"`
	Extensions             map[string]interface{}          `json:"extensions,omitempty"`
}

func NewPublicKeyCredentialCreationOptions(user model.User) (PublicKeyCredentialCreationOptions, error) {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return PublicKeyCredentialCreationOptions{}, errors.New("failed to generate challenge")
	}
	return PublicKeyCredentialCreationOptions{
		Challenge:   challenge,
		Attestation: "none",
		PubKeyCredParams: []PublicKeyCredentialParameters{{
			Type: "public-key",
			Alg:  -7,
		}},
		Rp: PublicKeyCredentialRpEntity{
			PublicKeyCredentialEntity: PublicKeyCredentialEntity{
				Name: "MyService",
			},
			Id: "localhost",
		},
		User: PublicKeyCredentialUserEntity{
			PublicKeyCredentialEntity: PublicKeyCredentialEntity{
				Name: user.Name,
			},
			Id:          user.Id,
			DisplayName: user.DisplayName,
		},
	}, nil
}

type AuthenticatorAttestationResponse struct {
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AttestationObject []byte `json:"attestationObject"`
}

type AuthenticatorFlags struct {
	UP bool
	UV bool
	BE bool
	BS bool
	AT bool
	ED bool
}

func NewAuthenticatorFlags(flags byte) AuthenticatorFlags {
	var af AuthenticatorFlags
	if 0x1&flags == 0x1 {
		af.UP = true
	}
	if 0x4&flags == 0x4 {
		af.UV = true
	}
	if 0x8&flags == 0x8 {
		af.BE = true
	}
	if 0x10&flags == 0x10 {
		af.BS = true
	}
	if 0x40&flags == 0x40 {
		af.AT = true
	}
	if 0x80&flags == 0x80 {
		af.ED = true
	}
	return af
}

type AttestedCredentialData struct {
	AAGUId              []byte                 `json:"aaguid"`
	CredentialIdLength  uint16                 `json:"credentialIdLength"`
	CredentialId        []byte                 `json:"credentialId"`
	CredentialPublicKey map[string]interface{} `json:"credentialPublicKey"`
}

type Extensions map[string]interface{}

func NewAttestedCredentialData(data []byte) (AttestedCredentialData, Extensions, error) {
	credentialIdLength := uint16(binary.BigEndian.Uint16(data[16:18]))
	if credentialIdLength > 1023 {
		return AttestedCredentialData{}, nil, errors.New("credentialIdLength is not valid")
	}
	credPubKey := make(map[string]any)
	extByte, err := cbor.UnmarshalFirst(data[credentialIdLength:], credPubKey)
	if err != nil {
		return AttestedCredentialData{}, nil, errors.New("credentialPublicKey is not valid")
	}

	ext := make(Extensions)
	if err := cbor.Unmarshal(extByte, ext); err != nil {
		return AttestedCredentialData{}, nil, errors.New("extensions is not valid")
	}
	return AttestedCredentialData{
		AAGUId:              data[:16],
		CredentialIdLength:  credentialIdLength,
		CredentialId:        data[18:credentialIdLength],
		CredentialPublicKey: credPubKey,
	}, ext, nil
}

type AuthenticatorData struct {
	RpIdHash               []byte                 `json:"rpIdHash"`
	Flags                  AuthenticatorFlags     `json:"flags"`
	SignCount              uint32                 `json:"signCount"`
	AttestedCredentialData AttestedCredentialData `json:"attestedCredentialData"`
	Extensions             Extensions             `json:"extensions"`
}

func (a *AuthenticatorData) Unmarshal(data []byte) error {
	a.RpIdHash = data[:32]
	a.Flags = NewAuthenticatorFlags(data[32])
	a.SignCount = uint32(binary.BigEndian.Uint32(data[33:37]))
	return nil
}

func NewAuthData(data []byte) (AuthenticatorData, error) {
	defaultAuthData := data[:37]
	optionAuthData := data[37:]

	authData := AuthenticatorData{
		RpIdHash:  defaultAuthData[:32],
		Flags:     NewAuthenticatorFlags(defaultAuthData[32]),
		SignCount: uint32(binary.BigEndian.Uint32(defaultAuthData[33:])),
	}

	var err error
	if authData.Flags.AT {
		authData.AttestedCredentialData, authData.Extensions, err = NewAttestedCredentialData(optionAuthData)
		if err != nil {
			return AuthenticatorData{}, err
		}
	} else if authData.Flags.ED {
		if err = cbor.Unmarshal(optionAuthData, authData.Extensions); err != nil {
			return AuthenticatorData{}, err
		}
	}

	return authData, nil
}

type CollectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	TopOrigin   string `json:"topOrigin,omitempty"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

type AttestationObject struct {
	Fmt      string            `json:"fmt"`
	AuthData []byte            `json:"authData"`
	AttStmt  map[string]string `json:"attStmt"`
}
