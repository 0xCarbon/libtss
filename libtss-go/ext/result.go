package ext

import "github.com/0xCarbon/libtss-go/tss"

type DKGResult struct {
	KeyShare         *tss.KeyShareHandle
	PublicKeyPackage tss.PublicKeyPackage
}

type SignResult = tss.Signature

type RefreshResult = DKGResult
