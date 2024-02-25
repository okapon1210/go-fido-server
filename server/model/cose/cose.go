package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

type COSEAlgorithmIdentifier int32

const (
	ES256 = -7
	ES384 = -35
	ES512 = -36
)

func (id COSEAlgorithmIdentifier) GetHashFunc() hash.Hash {
	switch id {
	case ES256:
		return crypto.SHA256.New()
	case ES384:
		return crypto.SHA384.New()
	case ES512:
		return crypto.SHA512.New()
	default:
		return nil
	}
}

type CredentialPublicKey interface {
	AlgType() COSEAlgorithmIdentifier
	KeyType() KeyType
}

// [7. Key Object Parameters](https://www.rfc-editor.org/rfc/rfc9053.html#name-key-object-parameters)
type KeyType int

const (
	OKP       KeyType = 1
	EC2       KeyType = 2
	Symmetric KeyType = 4
)

type CredentialPublicKeyBase struct {
	Kty     KeyType                 `cbor:"1,keyasint"`
	Kid     []byte                  `cbor:"2,keyasint,omitempty"`
	Alg     COSEAlgorithmIdentifier `cbor:"3,keyasint,omitempty"`
	KeyOpts []int                   `cbor:"4,keyasint,omitempty"`
	BaseIV  []byte                  `cbor:"5,keyasint,omitempty"`
}

func UnmarshalCredentialPublcKey(data []byte) (CredentialPublicKey, []byte, error) {
	var credPubkey CredentialPublicKeyBase
	_, err := cbor.UnmarshalFirst(data, &credPubkey)
	if err != nil {
		return nil, nil, err
	}
	switch credPubkey.Kty {
	case EC2:
		var ec2PubKey EC2PublicKey
		ext, err := cbor.UnmarshalFirst(data, &ec2PubKey)
		if err != nil {
			return nil, nil, err
		}
		return ec2PubKey, ext, nil
	default:
		return nil, nil, errors.New("kty is not valid")
	}
}

// [7.1. Elliptic Curve Keys](https://www.rfc-editor.org/rfc/rfc9053.html#name-elliptic-curve-keys)
type CurveType int

const (
	P256 CurveType = 1 + iota
	P384
	P521
	X25519
	X448
	Ed25519
	Ed448
)

// [7.1.1. Double Coordinate Curves](https://www.rfc-editor.org/rfc/rfc9053.html#name-double-coordinate-curves)
type EC2PublicKey struct {
	CredentialPublicKeyBase
	Crv CurveType `cbor:"-1,keyasint"`
	X   []byte    `cbor:"-2,keyasint"`
	Y   []byte    `cbor:"-3,keyasint"`
}

func (k EC2PublicKey) Verify(base, signature []byte) error {
	var crv elliptic.Curve
	switch k.Crv {
	case P256:
		crv = elliptic.P256()
	case P384:
		crv = elliptic.P384()
	case P521:
		crv = elliptic.P521()
	default:
		return fmt.Errorf("CurveType is not valid crv: %v", k.Crv)
	}

	publicKey := ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(k.X),
		Y:     big.NewInt(0).SetBytes(k.Y),
	}

	var esig EcdsaSignature
	if _, err := asn1.Unmarshal(signature, &esig); err != nil {
		return err
	}

	hasher := k.Alg.GetHashFunc()
	hasher.Write(base)

	if !ecdsa.Verify(&publicKey, hasher.Sum(nil), esig.R, esig.S) {
		return errors.New("invalid signature")
	}

	return nil
}

func (k EC2PublicKey) KeyType() KeyType {
	return k.Kty
}

func (k EC2PublicKey) AlgType() COSEAlgorithmIdentifier {
	return k.Alg
}

type EcdsaSignature struct {
	R, S *big.Int
}
