package model

import "example.com/model/cose"

type CredentialRecord struct {
	Type                  string
	Id                    string
	PublicKey             cose.CredentialPublicKey
	SignCount             uint32
	Flags                 AuthenticatorFlags
	Transports            []string
	AttestationObject     AttestationObject
	AttestationClientData CollectedClientData
}
