package tss

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

type Protocol uint8

const (
	ProtocolFROST  Protocol = 0
	ProtocolDKLs23 Protocol = 1
)

type Ciphersuite uint8

const (
	CiphersuiteSecp256k1Taproot Ciphersuite = 0
	CiphersuiteSecp256k1        Ciphersuite = 1
	CiphersuiteEd25519          Ciphersuite = 2
	CiphersuiteP256             Ciphersuite = 3
	CiphersuiteRistretto255     Ciphersuite = 4
	CiphersuiteEd448            Ciphersuite = 5
	CiphersuiteSecp256k1ECDSA   Ciphersuite = 6
)

func (c Ciphersuite) Protocol() Protocol {
	if c == CiphersuiteSecp256k1ECDSA {
		return ProtocolDKLs23
	}
	return ProtocolFROST
}

func (c Ciphersuite) MarshalJSON() ([]byte, error) {
	var name string
	switch c {
	case CiphersuiteSecp256k1Taproot:
		name = "Secp256k1Taproot"
	case CiphersuiteSecp256k1:
		name = "Secp256k1"
	case CiphersuiteEd25519:
		name = "Ed25519"
	case CiphersuiteP256:
		name = "P256"
	case CiphersuiteRistretto255:
		name = "Ristretto255"
	case CiphersuiteEd448:
		name = "Ed448"
	case CiphersuiteSecp256k1ECDSA:
		name = "Secp256k1ECDSA"
	default:
		return nil, fmt.Errorf("unknown ciphersuite %d", c)
	}
	return json.Marshal(name)
}

func (c *Ciphersuite) UnmarshalJSON(data []byte) error {
	var numeric uint8
	if err := json.Unmarshal(data, &numeric); err == nil {
		*c = Ciphersuite(numeric)
		return nil
	}

	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	switch strings.ToLower(name) {
	case "secp256k1taproot":
		*c = CiphersuiteSecp256k1Taproot
	case "secp256k1":
		*c = CiphersuiteSecp256k1
	case "ed25519":
		*c = CiphersuiteEd25519
	case "p256":
		*c = CiphersuiteP256
	case "ristretto255":
		*c = CiphersuiteRistretto255
	case "ed448":
		*c = CiphersuiteEd448
	case "secp256k1ecdsa":
		*c = CiphersuiteSecp256k1ECDSA
	default:
		return fmt.Errorf("unknown ciphersuite %q", name)
	}
	return nil
}

type Identifier uint16

type ThresholdConfig struct {
	MinSigners uint16
	MaxSigners uint16
	Suite      Ciphersuite
}

func (c ThresholdConfig) Validate() error {
	if c.MinSigners < 2 {
		return fmt.Errorf("min signers must be at least 2")
	}
	if c.MaxSigners < c.MinSigners {
		return fmt.Errorf("max signers must be >= min signers")
	}
	return nil
}

type Signature struct {
	Protocol Protocol
	Data     []byte
}

type PublicKeyPackage struct {
	Suite           Ciphersuite
	VerifyingKey    []byte
	VerifyingShares map[Identifier][]byte
	MinSigners      uint16
	MaxSigners      uint16
}

func decodePublicKeyPackage(data []byte) (PublicKeyPackage, error) {
	if len(data) < 7 {
		return PublicKeyPackage{}, fmt.Errorf("PublicKeyPackage too short: %d bytes", len(data))
	}
	pos := 0
	suite := Ciphersuite(data[pos])
	pos++
	minSigners := binary.LittleEndian.Uint16(data[pos:])
	pos += 2
	vkLen := int(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4
	if pos+vkLen > len(data) {
		return PublicKeyPackage{}, fmt.Errorf("truncated verifying key")
	}
	verifyingKey := append([]byte(nil), data[pos:pos+vkLen]...)
	pos += vkLen
	if pos+2 > len(data) {
		return PublicKeyPackage{}, fmt.Errorf("truncated share count")
	}
	shareCount := int(binary.LittleEndian.Uint16(data[pos:]))
	pos += 2
	shares := make(map[Identifier][]byte, shareCount)
	for range shareCount {
		if pos+6 > len(data) {
			return PublicKeyPackage{}, fmt.Errorf("truncated share header")
		}
		id := Identifier(binary.LittleEndian.Uint16(data[pos:]))
		sLen := int(binary.LittleEndian.Uint32(data[pos+2:]))
		pos += 6
		if pos+sLen > len(data) {
			return PublicKeyPackage{}, fmt.Errorf("truncated share data")
		}
		shares[id] = append([]byte(nil), data[pos:pos+sLen]...)
		pos += sLen
	}
	return PublicKeyPackage{
		Suite:           suite,
		VerifyingKey:    verifyingKey,
		VerifyingShares: shares,
		MinSigners:      minSigners,
		MaxSigners:      uint16(shareCount),
	}, nil
}
