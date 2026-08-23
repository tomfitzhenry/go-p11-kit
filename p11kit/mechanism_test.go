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
	"reflect"
	"testing"
)

// mechanismListRequest builds a C_GetMechanismList request body with the v0
// wire format "ufu": slot id and a ulong buffer for the mechanism count.
func mechanismListRequest(slotID uint64, count uint32) *body {
	var b buffer
	b.addUint64(slotID)
	b.addUint32(count)
	return &body{call: callGetMechanismList, signature: "ufu", buffer: newBuffer(b.bytes())}
}

// mechanismInfoRequest builds a C_GetMechanismInfo request body with the v0
// wire format "uu": slot id and mechanism type.
func mechanismInfoRequest(slotID, mechanism uint64) *body {
	var b buffer
	b.addUint64(slotID)
	b.addUint64(mechanism)
	return &body{call: callGetMechanismInfo, signature: "uu", buffer: newBuffer(b.bytes())}
}

func TestMechanismsDefault(t *testing.T) {
	s := Slot{}
	want := []uint64{ckmRSAKeyPairGen, ckmRSAPKCS, ckmRSAPKCSPSS, ckmECKeyPairGen, ckmECDSA, ckmECDH1Derive}
	got := s.mechanisms()
	if len(got) != len(want) {
		t.Fatalf("mechanisms() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mechanisms()[%d] = 0x%x, want 0x%x", i, got[i], want[i])
		}
	}
}

func TestMechanismsConfigured(t *testing.T) {
	s := Slot{Mechanisms: []uint64{ckmECDH1Derive, ckmECDSA}}
	want := []uint64{ckmECDH1Derive, ckmECDSA}
	got := s.mechanisms()
	if len(got) != len(want) {
		t.Fatalf("mechanisms() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mechanisms()[%d] = 0x%x, want 0x%x", i, got[i], want[i])
		}
	}
}

func TestMechanismInfoDefault(t *testing.T) {
	s := Slot{}
	if _, _, _, err := s.mechanismInfo(ckmECDSA); err != nil {
		t.Errorf("mechanismInfo(ckmECDSA) err = %v, want nil", err)
	}
	if _, _, _, err := s.mechanismInfo(0xdeadbeef); err == nil {
		t.Error("mechanismInfo(0xdeadbeef) err = nil, want errMechanismInvalid")
	}
}

func TestMechanismInfoConfigured(t *testing.T) {
	s := Slot{MechanismInfo: func(m uint64) (uint64, uint64, uint64, error) {
		if m == ckmECDSA {
			return 1, 2, 3, nil
		}
		return 0, 0, 0, errMechanismInvalid
	}}

	min, max, flags, err := s.mechanismInfo(ckmECDSA)
	if err != nil {
		t.Fatalf("mechanismInfo(ckmECDSA) err = %v, want nil", err)
	}
	if min != 1 || max != 2 || flags != 3 {
		t.Errorf("mechanismInfo(ckmECDSA) = (%d, %d, %d), want (1, 2, 3)", min, max, flags)
	}

	if _, _, _, err := s.mechanismInfo(ckmRSAKeyPairGen); err == nil {
		t.Error("mechanismInfo(ckmRSAKeyPairGen) err = nil, want errMechanismInvalid")
	}
}

func TestHandleGetMechanismList(t *testing.T) {
	h := &handler{s: &Handler{Slots: []Slot{{
		ID:         0x01,
		Mechanisms: []uint64{ckmECDH1Derive},
	}}}}

	// First query with count 0, the client asking for the number of mechanisms.
	resp, err := h.handleGetMechanismList(mechanismListRequest(0x01, 0))
	if err != nil {
		t.Fatalf("handleGetMechanismList(count=0): %v", err)
	}
	buf := newBuffer(resp.buffer.bytes())
	var present byte
	var n uint32
	if !buf.byte(&present) || !buf.uint32(&n) {
		t.Fatal("parsing mechanism list response")
	}
	if present != 0 || n != 1 {
		t.Errorf("count response = (%d, %d), want (0, 1)", present, n)
	}

	// Second query with a big enough count, the client asking for the list.
	resp, err = h.handleGetMechanismList(mechanismListRequest(0x01, 4))
	if err != nil {
		t.Fatalf("handleGetMechanismList(count=4): %v", err)
	}
	buf = newBuffer(resp.buffer.bytes())
	var mechanisms []uint64
	if !buf.byte(&present) || !buf.uint32(&n) {
		t.Fatal("parsing mechanism list response")
	}
	for i := uint32(0); i < n; i++ {
		var m uint64
		if !buf.uint64(&m) {
			t.Fatal("parsing mechanism list entry")
		}
		mechanisms = append(mechanisms, m)
	}
	if !reflect.DeepEqual(mechanisms, []uint64{ckmECDH1Derive}) {
		t.Errorf("mechanism list = %v, want [0x%x]", mechanisms, ckmECDH1Derive)
	}
}

func TestHandleGetMechanismInfo(t *testing.T) {
	h := &handler{s: &Handler{Slots: []Slot{{
		ID: 0x01,
		MechanismInfo: func(m uint64) (uint64, uint64, uint64, error) {
			if m == ckmECDH1Derive {
				return 32, 32, ckfDerive, nil
			}
			return 0, 0, 0, errMechanismInvalid
		},
	}}}}

	resp, err := h.handleGetMechanismInfo(mechanismInfoRequest(0x01, ckmECDH1Derive))
	if err != nil {
		t.Fatalf("handleGetMechanismInfo: %v", err)
	}
	buf := newBuffer(resp.buffer.bytes())
	var min, max, flags uint64
	if !buf.uint64(&min) || !buf.uint64(&max) || !buf.uint64(&flags) {
		t.Fatal("parsing mechanism info response")
	}
	if min != 32 || max != 32 || flags != ckfDerive {
		t.Errorf("mechanism info = (%d, %d, 0x%x), want (32, 32, 0x%x)", min, max, flags, ckfDerive)
	}

	if _, err := h.handleGetMechanismInfo(mechanismInfoRequest(0x01, ckmECDSA)); err == nil {
		t.Error("handleGetMechanismInfo(ckmECDSA) err = nil, want errMechanismInvalid")
	}
}
