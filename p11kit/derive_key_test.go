// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package p11kit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// TestX963KDF verifies the ANSI X9.63 KDF against vectors computed
// independently (pycryptodome/Python implementation of the same construction).
func TestX963KDF(t *testing.T) {
	z := []byte{
		0x53, 0x55, 0x98, 0x82, 0x72, 0xa7, 0x08, 0xa2,
		0xae, 0x3a, 0x0b, 0xc4, 0x74, 0x12, 0x22, 0xf2,
		0x06, 0xb1, 0xad, 0x81, 0xfa, 0x97, 0xb2, 0x83,
		0x69, 0xa0, 0x2a, 0xa6, 0xc0, 0xb0, 0x8b, 0x8b,
	}
	shared := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	tests := []struct {
		name   string
		kdf    uint64
		outLen int
		shared []byte
		want   string
	}{
		{"SHA224", ckdSHA224KDF, 28, shared, "8bc730a61fcaec33f6e82d7c591b9df3311ef66b81bd5bdde3d5129b"},
		{"SHA256", ckdSHA256KDF, 32, shared, "7f6c76ea19ee279b7800712867a458a65fb506824727bad328719a52c432f620"},
		{"SHA256MultiBlock", ckdSHA256KDF, 48, shared, "7f6c76ea19ee279b7800712867a458a65fb506824727bad328719a52c432f6202e258d89a26231ee1cffee3e9025652c"},
		{"SHA256NoSharedData", ckdSHA256KDF, 64, nil, "67d72d20afe2222bf50f9595f9e1eaf202b3d2b18bab49aa6883fcc4db15fe68652b5633cbf8729e7031331f93e1a177f67b2a8dd58b15d6332482a99354fedd"},
		{"SHA384", ckdSHA384KDF, 48, shared, "031643d8c92a036742a7d17d4a018740440582743999414c672e53eceb23968ccf5b9c94bace62bf0d2fb95a328dbf5a"},
		{"SHA512", ckdSHA512KDF, 64, shared, "bc94986015d5445832b268be347ba944519aabf2d088a172cfdb099700d1faed64bcb5ea1b61fab04e0937dd97ee5c3c1d04c8e9676ccb1635a0890d4aeda5a2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := hashForKDF(tt.kdf)
			if err != nil {
				t.Fatalf("hashForKDF: %v", err)
			}
			got, err := x963KDF(z, h, tt.shared, tt.outLen)
			if err != nil {
				t.Fatalf("x963KDF: %v", err)
			}
			if gotHex := hex.EncodeToString(got); gotHex != tt.want {
				t.Errorf("x963KDF = %s, want %s", gotHex, tt.want)
			}
		})
	}

	if _, err := x963KDF(z, sha256.New, shared, 0); !errors.Is(err, errMechanismParamInvalid) {
		t.Errorf("x963KDF with zero length = %v, want %v", err, errMechanismParamInvalid)
	}
}

// ecdhPoint returns the ANSI X9.62 uncompressed encoding of a public point.
func ecdhPoint(pub *ecdsa.PublicKey) []byte {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	point := make([]byte, 1+2*byteLen)
	point[0] = 0x04
	pub.X.FillBytes(point[1 : 1+byteLen])
	pub.Y.FillBytes(point[1+byteLen : 1+2*byteLen])
	return point
}

// deriveKeyRequest builds a C_DeriveKey request body with the v0 wire format
// "uMuaA": session id, mechanism, base key id, attribute template.
func deriveKeyRequest(sessionID uint64, m mechanism, keyID uint64, tmpl []attribute) *body {
	var b buffer
	b.addUint64(sessionID)
	b.addUint32(m.typ)
	if !mechanismHasNoParameters(m.typ) {
		b.addByte(1)
		switch p := m.params.(type) {
		case ecdh1DeriveParams:
			b.addUint64(p.kdf)
			b.addByteArray(p.sharedData)
			b.addByteArray(p.publicData)
		default:
			panic("unhandled mechanism parameters")
		}
	}
	b.addUint64(keyID)
	b.addUint32(uint32(len(tmpl)))
	for _, a := range tmpl {
		b.addAttribute(a)
	}
	return &body{call: callDeriveKey, signature: "uMuaA", buffer: newBuffer(b.bytes())}
}

func newDeriveHandler(t *testing.T, base Object) (*handler, *session) {
	t.Helper()
	h := &handler{s: &Handler{}}
	s := &session{objects: []Object{base}}
	h.sessions = map[uint64]*session{1: s}
	return h, s
}

func TestHandleDeriveKey(t *testing.T) {
	basePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating base key: %v", err)
	}
	peerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating peer key: %v", err)
	}

	base, err := NewPrivateKeyObject(basePriv)
	if err != nil {
		t.Fatalf("creating base object: %v", err)
	}
	base.SetDerive()

	// The two parties must agree on the shared secret: the x-coordinate of
	// basePriv.D * peerPriv's point.
	sx, _ := basePriv.Curve.ScalarMult(peerPriv.X, peerPriv.Y, basePriv.D.Bytes())
	wantSecret := make([]byte, 32)
	sx.FillBytes(wantSecret)

	m := mechanism{typ: ckmECDH1Derive, params: ecdh1DeriveParams{
		kdf:        ckdNull,
		sharedData: []byte{},
		publicData: ecdhPoint(&peerPriv.PublicKey),
	}}

	class := ckoSecretKey
	keyType := ckkGenericSecret
	tmpl := []attribute{
		{typ: attributeClass, ulong: &class},
		{typ: attributeKeyType, ulong: &keyType},
	}

	h, s := newDeriveHandler(t, base)
	resp, err := h.handleDeriveKey(deriveKeyRequest(1, m, base.id, tmpl))
	if err != nil {
		t.Fatalf("handleDeriveKey: %v", err)
	}
	if len(s.objects) != 2 {
		t.Fatalf("session has %d objects, want 2", len(s.objects))
	}
	derived := s.objects[1]
	if derived.id != respBufferUlong(resp) {
		t.Errorf("derived key id = %d, response id = %d", derived.id, respBufferUlong(resp))
	}

	secret, ok := derived.attributeValue(attributeValue)
	if !ok {
		t.Fatalf("derived key has no CKA_VALUE")
	}
	if !bytesEq(secret.bytes, wantSecret) {
		t.Errorf("derived secret = %x, want %x", secret.bytes, wantSecret)
	}

	gotClass, _ := derived.attributeValue(attributeClass)
	var classVal uint64
	if !gotClass.setUint64(&classVal) || classVal != ckoSecretKey {
		t.Errorf("derived CKA_CLASS = %d, want %d", classVal, ckoSecretKey)
	}
}

// TestHandleDeriveKeySHA256 verifies an end-to-end C_DeriveKey with the
// CKM_ECDH1_DERIVE CKD_SHA256_KDF key derivation function.
func TestHandleDeriveKeySHA256(t *testing.T) {
	basePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating base key: %v", err)
	}
	peerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating peer key: %v", err)
	}

	base, err := NewPrivateKeyObject(basePriv)
	if err != nil {
		t.Fatalf("creating base object: %v", err)
	}
	base.SetDerive()

	shared := []byte{0x01, 0x02, 0x03, 0x04}
	valueLen := uint64(32)
	class := ckoSecretKey
	keyType := ckkGenericSecret
	tmpl := []attribute{
		{typ: attributeClass, ulong: &class},
		{typ: attributeKeyType, ulong: &keyType},
		{typ: attributeValueLen, ulong: &valueLen},
	}

	m := mechanism{typ: ckmECDH1Derive, params: ecdh1DeriveParams{
		kdf:        ckdSHA256KDF,
		sharedData: shared,
		publicData: ecdhPoint(&peerPriv.PublicKey),
	}}

	h, s := newDeriveHandler(t, base)
	resp, err := h.handleDeriveKey(deriveKeyRequest(1, m, base.id, tmpl))
	if err != nil {
		t.Fatalf("handleDeriveKey: %v", err)
	}
	derived := s.objects[1]
	if derived.id != respBufferUlong(resp) {
		t.Errorf("derived key id = %d, response id = %d", derived.id, respBufferUlong(resp))
	}

	// Expected: the raw ECDH shared secret run through the X9.63 KDF.
	sx, _ := basePriv.Curve.ScalarMult(peerPriv.X, peerPriv.Y, basePriv.D.Bytes())
	raw := make([]byte, 32)
	sx.FillBytes(raw)
	want, err := x963KDF(raw, sha256.New, shared, 32)
	if err != nil {
		t.Fatalf("x963KDF: %v", err)
	}

	secret, ok := derived.attributeValue(attributeValue)
	if !ok {
		t.Fatalf("derived key has no CKA_VALUE")
	}
	if !bytes.Equal(secret.bytes, want) {
		t.Errorf("derived secret = %x, want %x", secret.bytes, want)
	}
}

func TestHandleDeriveKeyErrors(t *testing.T) {
	newBase := func(t *testing.T) (Object, *ecdsa.PrivateKey) {
		t.Helper()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating base key: %v", err)
		}
		base, err := NewPrivateKeyObject(priv)
		if err != nil {
			t.Fatalf("creating base object: %v", err)
		}
		return base, priv
	}

	validM := func(t *testing.T, priv *ecdsa.PrivateKey) mechanism {
		t.Helper()
		return mechanism{typ: ckmECDH1Derive, params: ecdh1DeriveParams{
			kdf:        ckdNull,
			publicData: ecdhPoint(&priv.PublicKey),
		}}
	}

	t.Run("UnsupportedMechanism", func(t *testing.T) {
		base, _ := newBase(t)
		base.SetDerive()
		h, _ := newDeriveHandler(t, base)
		m := mechanism{typ: ckmRSAPKCS, params: []byte{}}
		_, err := h.handleDeriveKey(deriveKeyRequest(1, m, base.id, nil))
		if !errors.Is(err, errMechanismInvalid) {
			t.Fatalf("handleDeriveKey = %v, want %v", err, errMechanismInvalid)
		}
	})

	t.Run("DeriveNotPermitted", func(t *testing.T) {
		base, priv := newBase(t)
		h, _ := newDeriveHandler(t, base)
		_, err := h.handleDeriveKey(deriveKeyRequest(1, validM(t, priv), base.id, nil))
		if !errors.Is(err, errKeyFunctionNotPermitted) {
			t.Fatalf("handleDeriveKey = %v, want %v", err, errKeyFunctionNotPermitted)
		}
	})

	t.Run("UnsupportedKDF", func(t *testing.T) {
		base, priv := newBase(t)
		base.SetDerive()
		h, _ := newDeriveHandler(t, base)
		m := mechanism{typ: ckmECDH1Derive, params: ecdh1DeriveParams{
			kdf:        0x00000002, // CKD_SHA1_KDF, not implemented
			publicData: ecdhPoint(&priv.PublicKey),
		}}
		_, err := h.handleDeriveKey(deriveKeyRequest(1, m, base.id, nil))
		if !errors.Is(err, errMechanismParamInvalid) {
			t.Fatalf("handleDeriveKey = %v, want %v", err, errMechanismParamInvalid)
		}
	})

	t.Run("InvalidPeerPoint", func(t *testing.T) {
		base, _ := newBase(t)
		base.SetDerive()
		h, _ := newDeriveHandler(t, base)
		m := mechanism{typ: ckmECDH1Derive, params: ecdh1DeriveParams{
			kdf:        ckdNull,
			publicData: []byte{0x04, 0x01, 0x02, 0x03},
		}}
		_, err := h.handleDeriveKey(deriveKeyRequest(1, m, base.id, nil))
		if !errors.Is(err, errArgumentsBad) {
			t.Fatalf("handleDeriveKey = %v, want %v", err, errArgumentsBad)
		}
	})

	t.Run("MissingObject", func(t *testing.T) {
		base, priv := newBase(t)
		base.SetDerive()
		h, _ := newDeriveHandler(t, base)
		_, err := h.handleDeriveKey(deriveKeyRequest(1, validM(t, priv), 0xdeadbeef, nil))
		if !errors.Is(err, errObjectHandleInvalid) {
			t.Fatalf("handleDeriveKey = %v, want %v", err, errObjectHandleInvalid)
		}
	})
}

func TestReadMechanismECDH1(t *testing.T) {
	var b buffer
	b.addUint32(ckmECDH1Derive)
	b.addByte(1) // parameters present
	b.addUint64(ckdNull)
	b.addByteArray([]byte{0x01, 0x02}) // shared data
	b.addByteArray([]byte{0x04, 0x03}) // public data

	req := &body{signature: "M", buffer: newBuffer(b.bytes())}
	var m mechanism
	req.readMechanism(&m)
	if err := req.err(); err != nil {
		t.Fatalf("readMechanism: %v", err)
	}
	if m.typ != ckmECDH1Derive {
		t.Fatalf("mechanism type = 0x%x, want 0x%x", m.typ, ckmECDH1Derive)
	}
	p, ok := m.params.(ecdh1DeriveParams)
	if !ok {
		t.Fatalf("mechanism params = %T, want ecdh1DeriveParams", m.params)
	}
	if p.kdf != ckdNull {
		t.Errorf("kdf = %d, want %d", p.kdf, ckdNull)
	}
	if !bytesEq(p.sharedData, []byte{0x01, 0x02}) {
		t.Errorf("sharedData = %x, want %x", p.sharedData, []byte{0x01, 0x02})
	}
	if !bytesEq(p.publicData, []byte{0x04, 0x03}) {
		t.Errorf("publicData = %x, want %x", p.publicData, []byte{0x04, 0x03})
	}
}

// respBufferUlong reads a single ulong from a response body's buffer.
func respBufferUlong(resp *body) uint64 {
	b := newBuffer(resp.buffer.bytes())
	var n uint64
	b.uint64(&n)
	return n
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
