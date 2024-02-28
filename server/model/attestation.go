package model

import (
	"encoding/binary"
	"errors"

	"example.com/model/cose"
	"github.com/fxamacker/cbor/v2"
)

const (
	up byte = 1 << iota
	rfu1
	uv
	be
	bs
	rfu2
	at
	ed
)

type AuthenticatorFlags struct {
	UP bool
	UV bool
	BE bool
	BS bool
	AT bool
	ED bool
}

func ParseAuthenticatorFlags(flags byte) AuthenticatorFlags {
	return AuthenticatorFlags{
		UP: flags&up == up,
		UV: flags&uv == uv,
		BE: flags&be == be,
		BS: flags&bs == bs,
		AT: flags&at == at,
		ED: flags&ed == ed,
	}
}

type AttestedCredentialData struct {
	AAGUId              []byte                   `json:"aaguid"`
	CredentialIdLength  uint16                   `json:"credentialIdLength"`
	CredentialId        []byte                   `json:"credentialId"`
	CredentialPublicKey cose.CredentialPublicKey `json:"credentialPublicKey"`
}

func UnmarshalAttestedCredentialData(data []byte) (AttestedCredentialData, []byte, error) {
	credentialIdLength := uint16(binary.BigEndian.Uint16(data[16:18]))
	credentialIdEndLength := 18 + credentialIdLength
	credPubKey, ext, err := cose.UnmarshalCredentialPublcKey(data[credentialIdEndLength:])
	if err != nil {
		return AttestedCredentialData{}, nil, err
	}
	return AttestedCredentialData{
		AAGUId:              data[:16],
		CredentialIdLength:  credentialIdLength,
		CredentialId:        data[18:credentialIdEndLength],
		CredentialPublicKey: credPubKey,
	}, ext, nil
}

func NewAttestedCredentialData(data []byte, flags AuthenticatorFlags) (AttestedCredentialData, []byte, error) {
	credentialIdLength := uint16(binary.BigEndian.Uint16(data[16:18]))
	if credentialIdLength > 1023 {
		return AttestedCredentialData{}, nil, errors.New("credentialIdLength is not valid")
	}
	var credPubKey cose.EC2PublicKey
	extByte, err := cbor.UnmarshalFirst(data[18+credentialIdLength:], &credPubKey)
	if err != nil {
		return AttestedCredentialData{}, nil, errors.Join(errors.New("credentialPublicKey is not valid"), err)
	}

	return AttestedCredentialData{
		AAGUId:              data[:16],
		CredentialIdLength:  credentialIdLength,
		CredentialId:        data[18:credentialIdLength],
		CredentialPublicKey: credPubKey,
	}, extByte, nil
}

type AuthenticatorData struct {
	RpIdHash               []byte                 `json:"rpIdHash"`
	Flags                  AuthenticatorFlags     `json:"flags"`
	SignCount              uint32                 `json:"signCount"`
	AttestedCredentialData AttestedCredentialData `json:"attestedCredentialData"`
	Extensions             cbor.RawMessage        `json:"extensions"`
}

func UnmarshalAuthenticatorData(data []byte) (AuthenticatorData, error) {
	defaultAuthData := data[:37]
	optionAuthData := data[37:]

	authData := AuthenticatorData{
		RpIdHash:  defaultAuthData[:32],
		Flags:     ParseAuthenticatorFlags(defaultAuthData[32]),
		SignCount: binary.BigEndian.Uint32(defaultAuthData[33:]),
	}

	var err error
	extByte := optionAuthData
	if authData.Flags.AT {
		authData.AttestedCredentialData, extByte, err = UnmarshalAttestedCredentialData(optionAuthData)
		if err != nil {
			return AuthenticatorData{}, err
		}
	}

	if authData.Flags.ED {
		if err = cbor.Unmarshal(extByte, authData.Extensions); err != nil {
			return AuthenticatorData{}, err
		}
	}

	return authData, nil
}

type AttestationFormat string

const (
	Packed           AttestationFormat = "packed"
	Tpm              AttestationFormat = "tpm"
	AndroidKey       AttestationFormat = "android-key"
	AndroidSatetynet AttestationFormat = "android-safetynet"
	FidoU2F          AttestationFormat = "fido-u2f"
	Apple            AttestationFormat = "apple"
	None             AttestationFormat = "none"
)

type AttestationObject struct {
	Fmt      AttestationFormat `json:"fmt"`
	AttStmt  cbor.RawMessage   `json:"attStmt"`
	AuthData []byte            `json:"authData"`
}

// [8.2. Packed Attestation Statement Format](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation)
type PackedStatementFormat struct {
	Alg cose.COSEAlgorithmIdentifier `json:"alg"`
	Sig []byte                       `json:"sig"`
	// X5C
}
