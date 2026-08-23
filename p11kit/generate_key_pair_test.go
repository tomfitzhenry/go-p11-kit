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
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

// generateKeyPairRequest builds a C_GenerateKeyPair request body with the v0
// wire format "uMaAaA": session id, mechanism, public template, private
// template.
func generateKeyPairRequest(sessionID uint64, m mechanism, pubTmpl, privTmpl []attribute) *body {
	var b buffer
	b.addUint64(sessionID)
	b.addUint32(m.typ)
	if !mechanismHasNoParameters(m.typ) {
		panic("unhandled mechanism parameters")
	}
	b.addUint32(uint32(len(pubTmpl)))
	for _, a := range pubTmpl {
		b.addAttribute(a)
	}
	b.addUint32(uint32(len(privTmpl)))
	for _, a := range privTmpl {
		b.addAttribute(a)
	}
	return &body{call: callGenerateKeyPair, signature: "uMaAaA", buffer: newBuffer(b.bytes())}
}

func newGenerateKeyPairHandler(t *testing.T) (*handler, *session) {
	t.Helper()
	h := &handler{s: &Handler{Slots: []Slot{{ID: 0x01}}}}
	s := &session{slotID: 0x01}
	h.sessions = map[uint64]*session{1: s}
	return h, s
}

// respBufferUlongs reads two ulongs from a response body's buffer, returning
// them in order.
func respBufferUlongs(resp *body) (a, b uint64) {
	buf := newBuffer(resp.buffer.bytes())
	buf.uint64(&a)
	buf.uint64(&b)
	return a, b
}

func attributeUlong(t *testing.T, o Object, typ attributeType) uint64 {
	t.Helper()
	attr, ok := o.attributeValue(typ)
	if !ok {
		t.Fatalf("object has no attribute %s", typ)
	}
	var n uint64
	if !attr.setUint64(&n) {
		t.Fatalf("attribute %s is not an ulong", typ)
	}
	return n
}

func attributeBytes(t *testing.T, o Object, typ attributeType) []byte {
	t.Helper()
	attr, ok := o.attributeValue(typ)
	if !ok {
		t.Fatalf("object has no attribute %s", typ)
	}
	return attr.bytes
}

func TestHandleGenerateKeyPairRSA(t *testing.T) {
	label := []byte("rsa-key")
	bits := uint64(2048)
	pubTmpl := []attribute{
		{typ: attributeLabel, bytes: label},
		{typ: attributeModulusBits, ulong: &bits},
	}
	privTmpl := []attribute{
		{typ: attributeLabel, bytes: label},
	}

	h, s := newGenerateKeyPairHandler(t)
	resp, err := h.handleGenerateKeyPair(generateKeyPairRequest(1, mechanism{typ: ckmRSAKeyPairGen}, pubTmpl, privTmpl))
	if err != nil {
		t.Fatalf("handleGenerateKeyPair: %v", err)
	}
	if len(s.objects) != 2 {
		t.Fatalf("session has %d objects, want 2", len(s.objects))
	}
	pub, priv := s.objects[0], s.objects[1]

	pubID, privID := respBufferUlongs(resp)
	if pubID != pub.id || privID != priv.id {
		t.Errorf("response ids = %d/%d, want %d/%d", pubID, privID, pub.id, priv.id)
	}

	if got := attributeUlong(t, pub, attributeClass); got != ckoPublicKey {
		t.Errorf("public CKA_CLASS = %d, want %d", got, ckoPublicKey)
	}
	if got := attributeUlong(t, priv, attributeClass); got != ckoPrivateKey {
		t.Errorf("private CKA_CLASS = %d, want %d", got, ckoPrivateKey)
	}
	if got := attributeUlong(t, pub, attributeKeyType); got != ckkRSA {
		t.Errorf("public CKA_KEY_TYPE = %d, want %d", got, ckkRSA)
	}
	if got := attributeUlong(t, priv, attributeKeyType); got != ckkRSA {
		t.Errorf("private CKA_KEY_TYPE = %d, want %d", got, ckkRSA)
	}
	if got := attributeUlong(t, pub, attributeModulusBits); got != bits {
		t.Errorf("public CKA_MODULUS_BITS = %d, want %d", got, bits)
	}

	for i, o := range []Object{pub, priv} {
		if got := attributeBytes(t, o, attributeLabel); !bytes.Equal(got, label) {
			t.Errorf("object %d CKA_LABEL = %q, want %q", i, got, label)
		}
	}

	// The generated pair must be findable by label.
	s.find(1, []attribute{{typ: attributeLabel, bytes: label}})
	if len(s.findMatches) != 2 {
		t.Errorf("find by label matched %d objects, want 2", len(s.findMatches))
	}
}

func TestHandleGenerateKeyPairEC(t *testing.T) {
	params, err := asn1.Marshal(oidNamedCurveP256)
	if err != nil {
		t.Fatalf("marshaling curve oid: %v", err)
	}
	label := []byte("ec-key")
	pubTmpl := []attribute{
		{typ: attributeLabel, bytes: label},
		{typ: attributeECParams, bytes: params},
	}
	privTmpl := []attribute{
		{typ: attributeLabel, bytes: label},
	}

	h, s := newGenerateKeyPairHandler(t)
	resp, err := h.handleGenerateKeyPair(generateKeyPairRequest(1, mechanism{typ: ckmECKeyPairGen}, pubTmpl, privTmpl))
	if err != nil {
		t.Fatalf("handleGenerateKeyPair: %v", err)
	}
	pub, priv := s.objects[0], s.objects[1]

	pubID, privID := respBufferUlongs(resp)
	if pubID != pub.id || privID != priv.id {
		t.Errorf("response ids = %d/%d, want %d/%d", pubID, privID, pub.id, priv.id)
	}

	if got := attributeUlong(t, pub, attributeKeyType); got != ckkECDSA {
		t.Errorf("public CKA_KEY_TYPE = %d, want %d", got, ckkECDSA)
	}
	if got := attributeUlong(t, priv, attributeKeyType); got != ckkECDSA {
		t.Errorf("private CKA_KEY_TYPE = %d, want %d", got, ckkECDSA)
	}
	if point := attributeBytes(t, pub, attributeECPoint); len(point) == 0 {
		t.Error("public object has an empty CKA_EC_POINT")
	}
	if got := attributeBytes(t, pub, attributeECParams); !bytes.Equal(got, params) {
		t.Errorf("public CKA_EC_PARAMS = %x, want %x", got, params)
	}

	// The private key must be usable for signing.
	privObj := priv
	if _, ok := privObj.priv.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("generated private key is %T, want *ecdsa.PrivateKey", privObj.priv)
	}
	digest := sha256.Sum256([]byte("hello"))
	m := mechanism{typ: ckmECDSA, params: []byte{}}
	if _, err := privObj.sign(m, digest[:]); err != nil {
		t.Errorf("signing with generated key: %v", err)
	}
}

// TestHandleGenerateKeyPairECAllCurves verifies that every supported named
// curve can be generated and the resulting key's public half matches the
// curve.
func TestHandleGenerateKeyPairECAllCurves(t *testing.T) {
	for _, tc := range []struct {
		name  string
		oid   asn1.ObjectIdentifier
		curve elliptic.Curve
	}{
		{"P-224", oidNamedCurveP224, elliptic.P224()},
		{"P-256", oidNamedCurveP256, elliptic.P256()},
		{"P-384", oidNamedCurveP384, elliptic.P384()},
		{"P-521", oidNamedCurveP521, elliptic.P521()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := asn1.Marshal(tc.oid)
			if err != nil {
				t.Fatalf("marshaling curve oid: %v", err)
			}
			pubTmpl := []attribute{{typ: attributeECParams, bytes: params}}
			h, s := newGenerateKeyPairHandler(t)
			if _, err := h.handleGenerateKeyPair(generateKeyPairRequest(1, mechanism{typ: ckmECKeyPairGen}, pubTmpl, nil)); err != nil {
				t.Fatalf("handleGenerateKeyPair: %v", err)
			}
			priv := s.objects[1]
			got := priv.priv.Public().(*ecdsa.PublicKey)
			if got.Curve != tc.curve {
				t.Errorf("generated key curve = %v, want %v", got.Curve.Params().Name, tc.curve.Params().Name)
			}
		})
	}
}

func TestHandleGenerateKeyPairErrors(t *testing.T) {
	tests := []struct {
		name    string
		m       mechanism
		pubTmpl []attribute
		want    error
	}{
		{"UnsupportedMechanism", mechanism{typ: ckmRSAPKCS}, nil, errMechanismInvalid},
		{"RSAMissingModulusBits", mechanism{typ: ckmRSAKeyPairGen}, nil, errTemplateIncomplete},
		{"RSASmallKey", mechanism{typ: ckmRSAKeyPairGen}, func() []attribute {
			bits := uint64(512)
			return []attribute{{typ: attributeModulusBits, ulong: &bits}}
		}(), errKeySizeRange},
		{"RSAUnsupportedExponent", mechanism{typ: ckmRSAKeyPairGen}, func() []attribute {
			bits := uint64(2048)
			exp := big.NewInt(3).Bytes()
			return []attribute{
				{typ: attributeModulusBits, ulong: &bits},
				{typ: attributePublicExponent, bytes: exp},
			}
		}(), errAttributeValueInvalid},
		{"ECMissingParams", mechanism{typ: ckmECKeyPairGen}, nil, errTemplateIncomplete},
		{"ECUnsupportedCurve", mechanism{typ: ckmECKeyPairGen}, func() []attribute {
			bad, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 3, 4})
			if err != nil {
				t.Fatalf("marshaling oid: %v", err)
			}
			return []attribute{{typ: attributeECParams, bytes: bad}}
		}(), errCurveNotSupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, s := newGenerateKeyPairHandler(t)
			_, err := h.handleGenerateKeyPair(generateKeyPairRequest(1, tt.m, tt.pubTmpl, nil))
			if !errors.Is(err, tt.want) {
				t.Fatalf("handleGenerateKeyPair = %v, want %v", err, tt.want)
			}
			if len(s.objects) != 0 {
				t.Errorf("session gained %d objects on error, want 0", len(s.objects))
			}
		})
	}
}

func TestReadMechanismKeyPairGen(t *testing.T) {
	for _, m := range []uint32{ckmRSAKeyPairGen, ckmECKeyPairGen} {
		// p11-kit 0.24 and earlier append a NULL byte-array marker
		// (0xffffffff) after a parameter-less mechanism type.
		var b buffer
		b.addUint32(m)
		b.addUint32(0xffffffff)

		req := &body{signature: "M", buffer: newBuffer(b.bytes())}
		var mech mechanism
		req.readMechanism(&mech)
		if err := req.err(); err != nil {
			t.Fatalf("readMechanism(0x%x): %v", m, err)
		}
		if mech.typ != m {
			t.Errorf("mechanism type = 0x%x, want 0x%x", mech.typ, m)
		}

		// Since 0.26 the marker is omitted entirely.
		req = &body{signature: "M", buffer: newBuffer(mustBuffer(t, m))}
		req.readMechanism(&mech)
		if err := req.err(); err != nil {
			t.Fatalf("readMechanism(0x%x) without marker: %v", m, err)
		}
		if mech.typ != m {
			t.Errorf("mechanism type = 0x%x, want 0x%x", mech.typ, m)
		}
	}
}

func mustBuffer(t *testing.T, m uint32) []byte {
	t.Helper()
	var b buffer
	b.addUint32(m)
	return b.bytes()
}

// TestGenerateKeyPairMultipleSlots generates an EC key pair on one of two
// slots and verifies it is confined to that slot's session.
// TestGenerateKeyPairTokenPersistence verifies that keys generated with
// CKA_TOKEN set are stored on the slot's token and become findable by label in
// later sessions, rather than disappearing when the generating session ends.
func TestGenerateKeyPairTokenPersistence(t *testing.T) {
	params, err := asn1.Marshal(oidNamedCurveP256)
	if err != nil {
		t.Fatalf("marshaling curve oid: %v", err)
	}
	label := []byte("persisted-key")
	token := bTrue
	pubTmpl := []attribute{
		{typ: attributeLabel, bytes: label},
		{typ: attributeECParams, bytes: params},
		{typ: attributeToken, byte: token},
	}
	privTmpl := []attribute{{typ: attributeLabel, bytes: label}}

	h := &handler{s: &Handler{Slots: []Slot{{ID: 0x01}}}}
	genSession, err := h.newSession(0x01)
	if err != nil {
		t.Fatalf("opening session: %v", err)
	}
	if _, err := h.handleGenerateKeyPair(generateKeyPairRequest(genSession, mechanism{typ: ckmECKeyPairGen}, pubTmpl, privTmpl)); err != nil {
		t.Fatalf("handleGenerateKeyPair: %v", err)
	}

	// Both the public and private templates persist to the token.
	slot := &h.s.Slots[0]
	if len(slot.Objects) != 2 {
		t.Fatalf("slot has %d persisted objects, want 2", len(slot.Objects))
	}
	for _, o := range slot.Objects {
		if got := attributeBytes(t, o, attributeLabel); !bytes.Equal(got, label) {
			t.Errorf("persisted object CKA_LABEL = %q, want %q", got, label)
		}
	}

	// A new session on the same slot can find the keys by label.
	newSessionID, err := h.newSession(0x01)
	if err != nil {
		t.Fatalf("opening second session: %v", err)
	}
	s := h.sessions[newSessionID]
	s.find(newSessionID, []attribute{{typ: attributeLabel, bytes: label}})
	if len(s.findMatches) != 2 {
		t.Errorf("find by label in new session matched %d objects, want 2", len(s.findMatches))
	}
}

func TestGenerateKeyPairMultipleSlots(t *testing.T) {
	params, err := asn1.Marshal(oidNamedCurveP256)
	if err != nil {
		t.Fatalf("marshaling curve oid: %v", err)
	}
	label := []byte("multi-slot-key")

	// A public key object that already exists on slot 0x01, distinct from the
	// key generated below.
	base, err := NewPublicKeyObject(mustTestPub(t))
	if err != nil {
		t.Fatalf("creating base object: %v", err)
	}

	h := &handler{s: &Handler{Slots: []Slot{
		{ID: 0x01, Objects: []Object{base}},
		{ID: 0x02},
	}}}
	if _, err := h.newSession(0x01); err != nil {
		t.Fatalf("opening session on slot 0x01: %v", err)
	}
	slot2Session, err := h.newSession(0x02)
	if err != nil {
		t.Fatalf("opening session on slot 0x02: %v", err)
	}

	pubTmpl := []attribute{
		{typ: attributeLabel, bytes: label},
		{typ: attributeECParams, bytes: params},
	}
	privTmpl := []attribute{{typ: attributeLabel, bytes: label}}
	if _, err := h.handleGenerateKeyPair(generateKeyPairRequest(slot2Session, mechanism{typ: ckmECKeyPairGen}, pubTmpl, privTmpl)); err != nil {
		t.Fatalf("handleGenerateKeyPair: %v", err)
	}

	// The generated pair lands in the slot-0x02 session.
	s2 := h.sessions[slot2Session]
	if s2.slotID != 0x02 {
		t.Errorf("generating session slotID = 0x%x, want 0x02", s2.slotID)
	}
	if len(s2.objects) != 2 {
		t.Fatalf("slot 0x02 session has %d objects, want 2", len(s2.objects))
	}
	for _, o := range s2.objects {
		if got := attributeBytes(t, o, attributeLabel); !bytes.Equal(got, label) {
			t.Errorf("object CKA_LABEL = %q, want %q", got, label)
		}
	}

	// The other slot's session is untouched.
	for id, s := range h.sessions {
		if id == slot2Session {
			continue
		}
		if len(s.objects) != 1 {
			t.Errorf("slot 0x%x session has %d objects, want 1", s.slotID, len(s.objects))
		}
		if _, ok := s.objects[0].attributeValue(attributeLabel); ok {
			t.Errorf("slot 0x%x session unexpectedly has a labelled object", s.slotID)
		}
	}
}

func mustTestPub(t *testing.T) *rsa.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generating rsa key: %v", err)
	}
	return &priv.PublicKey
}
