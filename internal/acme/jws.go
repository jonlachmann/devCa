package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

var b64 = base64.RawURLEncoding

// jwsMsg is the RFC 8555 flattened JWS JSON serialization.
type jwsMsg struct {
	Protected  string          `json:"protected"`
	Payload    string          `json:"payload"`
	Signature  string          `json:"signature"`
	Header     json.RawMessage `json:"header,omitempty"`     // unprotected header: forbidden
	Signatures json.RawMessage `json:"signatures,omitempty"` // general serialization: forbidden
}

type jwsHeader struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	Kid   string          `json:"kid"`
	JWK   json.RawMessage `json:"jwk"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// parseJWS decodes the envelope and protected header; it does not verify.
func parseJWS(body []byte) (*jwsMsg, *jwsHeader, []byte, error) {
	var m jwsMsg
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, nil, nil, fmt.Errorf("request body is not a JWS: %v", err)
	}
	if len(m.Header) > 0 || len(m.Signatures) > 0 {
		return nil, nil, nil, errors.New("only flattened JWS with a protected header is allowed")
	}
	hb, err := b64.DecodeString(m.Protected)
	if err != nil {
		return nil, nil, nil, errors.New("bad protected header encoding")
	}
	var h jwsHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, nil, nil, errors.New("bad protected header JSON")
	}
	payload, err := b64.DecodeString(m.Payload)
	if err != nil {
		return nil, nil, nil, errors.New("bad payload encoding")
	}
	return &m, &h, payload, nil
}

// parseJWK returns the public key and its RFC 7638 thumbprint.
func parseJWK(raw json.RawMessage) (crypto.PublicKey, string, error) {
	var k jwk
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, "", errors.New("bad jwk")
	}
	var canon string
	var pub crypto.PublicKey
	switch k.Kty {
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, "", fmt.Errorf("unsupported curve %q", k.Crv)
		}
		size := (curve.Params().BitSize + 7) / 8
		x, err1 := b64.DecodeString(k.X)
		y, err2 := b64.DecodeString(k.Y)
		if err1 != nil || err2 != nil || len(x) != size || len(y) != size {
			return nil, "", errors.New("bad EC coordinates")
		}
		p, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, "", errors.New("EC point not on curve")
		}
		pub = p
		canon = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
	case "RSA":
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			return nil, "", errors.New("bad RSA key")
		}
		ei := int(new(big.Int).SetBytes(e).Int64())
		p := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: ei}
		if p.N.BitLen() < 2048 || ei < 3 || ei%2 == 0 {
			return nil, "", errors.New("RSA account keys must be at least 2048 bits")
		}
		pub = p
		canon = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
	case "OKP":
		x, err := b64.DecodeString(k.X)
		if k.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
			return nil, "", errors.New("bad OKP key")
		}
		pub = ed25519.PublicKey(x)
		canon = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, k.X)
	default:
		return nil, "", fmt.Errorf("unsupported key type %q", k.Kty)
	}
	sum := sha256.Sum256([]byte(canon))
	return pub, b64.EncodeToString(sum[:]), nil
}

// errBadAlg distinguishes badSignatureAlgorithm from other failures.
var errBadAlg = errors.New("unsupported or mismatched signature algorithm")

// verifyJWS checks the signature over protected.payload with pub.
func verifyJWS(m *jwsMsg, alg string, pub crypto.PublicKey) error {
	sig, err := b64.DecodeString(m.Signature)
	if err != nil {
		return errors.New("bad signature encoding")
	}
	input := []byte(m.Protected + "." + m.Payload)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		var h crypto.Hash
		switch {
		case alg == "ES256" && k.Curve == elliptic.P256():
			h = crypto.SHA256
		case alg == "ES384" && k.Curve == elliptic.P384():
			h = crypto.SHA384
		case alg == "ES512" && k.Curve == elliptic.P521():
			h = crypto.SHA512
		default:
			return errBadAlg
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return errors.New("bad signature length")
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest(h, input), r, s) {
			return errors.New("signature verification failed")
		}
	case *rsa.PublicKey:
		if alg != "RS256" {
			return errBadAlg
		}
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, digest(crypto.SHA256, input), sig) != nil {
			return errors.New("signature verification failed")
		}
	case ed25519.PublicKey:
		if alg != "EdDSA" {
			return errBadAlg
		}
		if !ed25519.Verify(k, input, sig) {
			return errors.New("signature verification failed")
		}
	default:
		return errBadAlg
	}
	return nil
}

func digest(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA384:
		s := sha512.Sum384(b)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(b)
		return s[:]
	}
	s := sha256.Sum256(b)
	return s[:]
}
