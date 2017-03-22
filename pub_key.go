package crypto

import (
	"bytes"
	"crypto/sha256"

	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/tendermint/ed25519"
	"github.com/tendermint/ed25519/extra25519"
	. "github.com/tendermint/go-common"
	data "github.com/tendermint/go-data"
	"github.com/tendermint/go-wire"
	"golang.org/x/crypto/ripemd160"
)

// PubKeyInner is now the interface itself, use PubKey struct in all code
type PubKeyInner interface {
	Address() []byte
	Bytes() []byte
	KeyString() string
	VerifyBytes(msg []byte, sig Signature) bool
	Equals(PubKey) bool
}

var pubKeyMapper data.Mapper

// register both public key types with go-data (and thus go-wire)
func init() {
	pubKeyMapper = data.NewMapper(PubKey{}).
		RegisterImplementation(PubKeyEd25519{}, NameEd25519, TypeEd25519).
		RegisterImplementation(PubKeySecp256k1{}, NameSecp256k1, TypeSecp256k1)
}

// PubKey add json serialization to PubKeyInner
type PubKey struct {
	PubKeyInner `json:"unwrap"`
}

func WrapPubKey(pk PubKeyInner) PubKey {
	if wrap, ok := pk.(PubKey); ok {
		pk = wrap.Unwrap()
	}
	return PubKey{pk}
}

func (p PubKey) Unwrap() PubKeyInner {
	pk := p.PubKeyInner
	for wrap, ok := pk.(PubKey); ok; wrap, ok = pk.(PubKey) {
		pk = wrap.PubKeyInner
	}
	return pk
}

func (p PubKey) MarshalJSON() ([]byte, error) {
	return pubKeyMapper.ToJSON(p.PubKeyInner)
}

func (p *PubKey) UnmarshalJSON(data []byte) (err error) {
	parsed, err := pubKeyMapper.FromJSON(data)
	if err == nil && parsed != nil {
		p.PubKeyInner = parsed.(PubKeyInner)
	}
	return
}

func (p PubKey) Empty() bool {
	return p.PubKeyInner == nil
}

func PubKeyFromBytes(pubKeyBytes []byte) (pubKey PubKey, err error) {
	err = wire.ReadBinaryBytes(pubKeyBytes, &pubKey)
	return
}

//-------------------------------------

// Implements PubKeyInner
type PubKeyEd25519 [32]byte

func (pubKey PubKeyEd25519) Address() []byte {
	w, n, err := new(bytes.Buffer), new(int), new(error)
	wire.WriteBinary(pubKey[:], w, n, err)
	if *err != nil {
		PanicCrisis(*err)
	}
	// append type byte
	encodedPubkey := append([]byte{TypeEd25519}, w.Bytes()...)
	hasher := ripemd160.New()
	hasher.Write(encodedPubkey) // does not error
	return hasher.Sum(nil)
}

func (pubKey PubKeyEd25519) Bytes() []byte {
	return wire.BinaryBytes(PubKey{pubKey})
}

func (pubKey PubKeyEd25519) VerifyBytes(msg []byte, sig_ Signature) bool {
	// make sure we use the same algorithm to sign
	sig, ok := sig_.Unwrap().(SignatureEd25519)
	if !ok {
		return false
	}
	pubKeyBytes := [32]byte(pubKey)
	sigBytes := [64]byte(sig)
	return ed25519.Verify(&pubKeyBytes, msg, &sigBytes)
}

func (p PubKeyEd25519) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(p[:])
}

func (p *PubKeyEd25519) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	copy(p[:], ref)
	return err
}

// For use with golang/crypto/nacl/box
// If error, returns nil.
func (pubKey PubKeyEd25519) ToCurve25519() *[32]byte {
	keyCurve25519, pubKeyBytes := new([32]byte), [32]byte(pubKey)
	ok := extra25519.PublicKeyToCurve25519(keyCurve25519, &pubKeyBytes)
	if !ok {
		return nil
	}
	return keyCurve25519
}

func (pubKey PubKeyEd25519) String() string {
	return Fmt("PubKeyEd25519{%X}", pubKey[:])
}

// Must return the full bytes in hex.
// Used for map keying, etc.
func (pubKey PubKeyEd25519) KeyString() string {
	return Fmt("%X", pubKey[:])
}

func (pubKey PubKeyEd25519) Equals(other PubKey) bool {
	if otherEd, ok := other.Unwrap().(PubKeyEd25519); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	} else {
		return false
	}
}

//-------------------------------------

// Implements PubKey.
// Compressed pubkey (just the x-cord),
// prefixed with 0x02 or 0x03, depending on the y-cord.
type PubKeySecp256k1 [33]byte

// Implements Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey PubKeySecp256k1) Address() []byte {
	hasherSHA256 := sha256.New()
	hasherSHA256.Write(pubKey[:]) // does not error
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha) // does not error
	return hasherRIPEMD160.Sum(nil)
}

func (pubKey PubKeySecp256k1) Bytes() []byte {
	return wire.BinaryBytes(PubKey{pubKey})
}

func (pubKey PubKeySecp256k1) VerifyBytes(msg []byte, sig_ Signature) bool {
	// and assert same algorithm to sign and verify
	sig, ok := sig_.Unwrap().(SignatureSecp256k1)
	if !ok {
		return false
	}

	pub__, err := secp256k1.ParsePubKey(pubKey[:], secp256k1.S256())
	if err != nil {
		return false
	}
	sig__, err := secp256k1.ParseDERSignature(sig[:], secp256k1.S256())
	if err != nil {
		return false
	}
	return sig__.Verify(Sha256(msg), pub__)
}

func (p PubKeySecp256k1) MarshalJSON() ([]byte, error) {
	return data.Encoder.Marshal(p[:])
}

func (p *PubKeySecp256k1) UnmarshalJSON(enc []byte) error {
	var ref []byte
	err := data.Encoder.Unmarshal(&ref, enc)
	copy(p[:], ref)
	return err
}

func (pubKey PubKeySecp256k1) String() string {
	return Fmt("PubKeySecp256k1{%X}", pubKey[:])
}

// Must return the full bytes in hex.
// Used for map keying, etc.
func (pubKey PubKeySecp256k1) KeyString() string {
	return Fmt("%X", pubKey[:])
}

func (pubKey PubKeySecp256k1) Equals(other PubKey) bool {
	if otherSecp, ok := other.Unwrap().(PubKeySecp256k1); ok {
		return bytes.Equal(pubKey[:], otherSecp[:])
	} else {
		return false
	}
}
