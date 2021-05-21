package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math/big"
)

type ellipticPublicKey struct {
	X, Y *big.Int
}

type Crypto struct {
	curve   elliptic.Curve
	privkey []byte
	pubkey  []byte
	pub_x   *big.Int
	pub_y   *big.Int
	secret  []byte
}

func (c *Crypto) GenerateKeys() {
	c.curve = elliptic.P256()

	var err error
	c.privkey, c.pub_x, c.pub_y, err = elliptic.GenerateKey(c.curve, rand.Reader)
	c.ExportPubkey()
	if err != nil {
		log.Printf("failed to generate keypair\n")
		return
	}
	log.Printf("keys generated, uncompressed pubkey: %x\n", c.pubkey)
}

func (c *Crypto) ExportPubkey() {
	c.pubkey = c.MarshalPubkey()
}
func (c *Crypto) MarshalPubkey() []byte {
	return elliptic.Marshal(c.curve, c.pub_x, c.pub_y)
}

// from: https://github.com/fd/ecdh, MIT
func (c *Crypto) ComputeSharedSecret(pubkey []byte, salt string) error {
	x, y := elliptic.Unmarshal(c.curve, pubkey)
	if x == nil {
		//log.Printf("failed to unmarshal pubkey: %x\n", pubkey)
		return errors.New("failed to unmarshal pubkey")
	}

	s, _ := c.curve.ScalarMult(x, y, c.privkey)
	if s == nil {
		//log.Printf("failed to compute secret with pubkey: %x\n", pubkey)
		return errors.New("failed to compute secret")
	}
	//log.Printf("computer shared secret: %x\n", s)

	// append hex string of md5 hash sum to secret before hmac hash
	md5_sum := md5.Sum([]byte(salt))
	salt_hash := []byte(hex.EncodeToString(md5_sum[:])) // [:] converts [16]byte to []byte

	secret_hash := hmac.New(sha256.New, s.Bytes())
	secret_hash.Write(append(s.Bytes(), salt_hash...))
	c.secret = secret_hash.Sum(nil)

	log.Printf("computed shared secret sha256: %x\n", c.secret)
	return nil
}

func (c *Crypto) RandomBytes(num int) []byte {
	token := make([]byte, num)
	rand.Read(token)
	return token
}
func (c *Crypto) RandomHexString(numhex int) string {
	return BytesToHexString(c.RandomBytes(numhex / 2))
}

// RemovePadding removes padding from a block of data
// from: https://github.com/cloudflare/redoctober/blob/master/padding/padding.go
func (c *Crypto) RemovePadding(b []byte) ([]byte, error) {
	l := int(b[len(b)-1])
	if l > 16 {
		return nil, errors.New("padding incorrect")
	}

	return b[:len(b)-l], nil
}

// AddPadding adds padding to a block of data
// from: https://github.com/cloudflare/redoctober/blob/master/padding/padding.go
func (c *Crypto) AddPadding(b []byte) []byte {
	l := 16 - len(b)%16
	padding := make([]byte, l)
	padding[l-1] = byte(l)
	return append(b, padding...)
}

// https://golang.org/src/crypto/cipher/example_test.go
// IV needs to be attacked to the ciphertext...
func (c *Crypto) EncryptAesCbc(plaintext []byte, key []byte) ([]byte, error) {
	var err error
	plaintext, err = c.PKCS7AddPadding(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	if err != nil {
		return nil, err
	}

	log.Printf("encrypted data, nonce: %x, ciphertext: %x\n", iv, ciphertext)
	return ciphertext, nil
}

// https://golang.org/src/crypto/cipher/example_test.go
// needs hmac auth
func (c *Crypto) DecryptAesCbc(ciphertext []byte, key []byte) ([]byte, error) {
	// CBC mode always works in whole blocks.
	if (len(ciphertext) % aes.BlockSize) != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:AES_BLOCK_LEN]
	ciphertext = ciphertext[AES_BLOCK_LEN:]

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	// if password doesn't match c2, message decrypt will give an "invalid PKCS padding" error
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext, err = c.PKCS7RemovePadding(ciphertext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	log.Printf("decrypted plaintext: %s\n", ciphertext)
	return ciphertext, nil
}

// PKCS7AddPadding right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
// https://github.com/go-web/tokenizer/blob/master/pkcs7.go
func (c *Crypto) PKCS7AddPadding(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New("invalid block size")
	}
	if b == nil || len(b) == 0 {
		return nil, errors.New("invalid PKCS7 data")
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// PKCS7RemovePadding validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
// https://github.com/go-web/tokenizer/blob/master/pkcs7.go
func (c *Crypto) PKCS7RemovePadding(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New("invalid block size")
	}
	if b == nil || len(b) == 0 {
		return nil, errors.New("invalid PKCS7 data")
	}
	if len(b)%blocksize != 0 {
		return nil, errors.New("invalid PKCS7 padding, padding is not in multiples of blocksize")
	}
	x := b[len(b)-1]
	n := int(x)
	if n == 0 || n > len(b) {
		return nil, errors.New("invalid PKCS7 padding length")
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != x {
			return nil, errors.New("invalid PKCS7 padding bytes")
		}
	}
	return b[:len(b)-n], nil
}
