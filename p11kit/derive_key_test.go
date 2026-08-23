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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

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
			kdf:        0x00000002, // CKD_SHA1_KDF, unsupported
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
