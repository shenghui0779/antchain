package antchain

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
)

const (
	// BIZID              = "a00e36c5"
	// ENDPOINT           = "https://rest.baas.alipay.com"
	CHAIN_CALL_FOR_BIZ = "/api/contract/chainCallForBiz"
	CHAIN_CALL         = "/api/contract/chainCall"
	SHAKE_HAND         = "/api/contract/shakeHand"
)

// PemBlockType pem block type which taken from the preamble.
type PemBlockType string

const (
	// RSAPKCS1 private key in PKCS#1
	RSAPKCS1 PemBlockType = "RSA PRIVATE KEY"
	// RSAPKCS8 private key in PKCS#8
	RSAPKCS8 PemBlockType = "PRIVATE KEY"
)

// X is a convenient alias for a map[string]interface{}.
type X map[string]interface{}

// PrivateKey RSA private key
type PrivateKey struct {
	key *rsa.PrivateKey
}

// Sign returns sha-with-rsa signature.
func (pk *PrivateKey) Sign(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	h := hash.New()
	h.Write(data)

	signature, err := rsa.SignPKCS1v15(rand.Reader, pk.key, hash, h.Sum(nil))

	if err != nil {
		return nil, err
	}

	return signature, nil
}

// NewPrivateKeyFromPemBlock returns new private key with pem block.
func NewPrivateKeyFromPemBlock(b []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(b)

	if block == nil {
		return nil, errors.New("invalid rsa private key for pem.Decode")
	}

	var (
		pk  interface{}
		err error
	)

	switch PemBlockType(block.Type) {
	case RSAPKCS1:
		pk, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case RSAPKCS8:
		pk, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}

	if err != nil {
		return nil, err
	}

	return &PrivateKey{key: pk.(*rsa.PrivateKey)}, nil
}

// NewPrivateKeyFromPemFile returns new private key with pem file.
func NewPrivateKeyFromPemFile(pemFile string) (*PrivateKey, error) {
	keyPath, err := filepath.Abs(pemFile)

	if err != nil {
		return nil, err
	}

	f, err := os.Open(keyPath)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)

	if err != nil {
		return nil, err
	}

	return NewPrivateKeyFromPemBlock(b)
}

// Identity 链账户对应的Identity
type Identity struct {
	Data string `json:"data"`
}

// GetIdentityByName 根据链账户名称获取对应的Identity
func GetIdentityByName(name string) *Identity {
	h := sha256.New()
	h.Write([]byte(name))

	return &Identity{
		Data: base64.StdEncoding.EncodeToString(h.Sum(nil)),
	}
}

type TokenID *big.Int

// GetTokenID 根据hash值(建议：md5)获取对应的tokenID(uint256)
func GetTokenID(hash string) TokenID {
	v, _ := big.NewInt(0).SetString(hash, 16)

	return TokenID(v)
}

// ParseOutput 解析合约方法返回的output
func ParseOutput(data string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(data)

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
