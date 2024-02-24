package model

import (
	"crypto/rand"
	"errors"

	"example.com/model/cose"
)

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
	Type string                       `json:"type"`
	Alg  cose.COSEAlgorithmIdentifier `json:"alg"`
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

func NewPublicKeyCredentialCreationOptions(user User) (PublicKeyCredentialCreationOptions, error) {
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
