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
	"errors"
	"strings"
	"testing"
)

// initTokenRequest builds a C_InitToken request body with the v0 wire format
// "uayz": slot id, pin byte array, NUL-terminated label.
func initTokenRequest(slotID uint64, pin, label string) *body {
	var b buffer
	b.addUint64(slotID)
	b.addByte(1)
	b.addByteArray([]byte(pin))
	b.addByteArray([]byte(label))
	return &body{call: callInitToken, signature: "uayz", buffer: newBuffer(b.bytes())}
}

func TestHandleInitToken(t *testing.T) {
	t.Run("UninitializedToken", func(t *testing.T) {
		h := &handler{s: &Handler{
			Slots: []Slot{{ID: 0x01, Label: "old-label"}},
		}}
		resp, err := h.handleInitToken(initTokenRequest(0x01, "so-pin", "new-label"))
		if err != nil {
			t.Fatalf("handleInitToken: %v", err)
		}
		if resp.signature != "" || resp.buffer.len() != 0 {
			t.Errorf("response = %q %x, want empty", resp.signature, resp.buffer.bytes())
		}
		slot := h.s.Slots[0]
		if slot.Label != "new-label" {
			t.Errorf("slot label = %q, want %q", slot.Label, "new-label")
		}
		if !slot.Initialized {
			t.Errorf("slot is not initialized after C_InitToken")
		}
	})

	t.Run("AlreadyInitialized", func(t *testing.T) {
		h := &handler{s: &Handler{
			Slots: []Slot{{ID: 0x01, Initialized: true}},
		}}
		_, err := h.handleInitToken(initTokenRequest(0x01, "so-pin", "new-label"))
		if !errors.Is(err, errCryptokiAlreadyInitialized) {
			t.Fatalf("handleInitToken = %v, want %v", err, errCryptokiAlreadyInitialized)
		}
		if got := h.s.Slots[0].Label; got != "" {
			t.Errorf("label mutated on already-initialized token: %q", got)
		}
	})

	t.Run("InvalidSlot", func(t *testing.T) {
		h := &handler{s: &Handler{
			Slots: []Slot{{ID: 0x01}},
		}}
		_, err := h.handleInitToken(initTokenRequest(0x02, "so-pin", "new-label"))
		if !errors.Is(err, errSlotIDInvalid) {
			t.Fatalf("handleInitToken = %v, want %v", err, errSlotIDInvalid)
		}
	})

	t.Run("MalformedRequest", func(t *testing.T) {
		h := &handler{s: &Handler{
			Slots: []Slot{{ID: 0x01}},
		}}
		req := &body{call: callInitToken, signature: "uayz", buffer: newBuffer(nil)}
		if _, err := h.handleInitToken(req); err == nil {
			t.Fatal("handleInitToken succeeded on a malformed request")
		}
	})
}

// tokenInfoFlags extracts the CK_TOKEN_INFO flags from a response body by
// skipping the four fixed-width strings that precede it.
func tokenInfoFlags(resp *body) (uint64, error) {
	var b buffer
	b.b = resp.buffer.bytes()
	for i := 0; i < 4; i++ {
		var n uint32
		if !b.uint32(&n) {
			return 0, errors.New("truncated string length")
		}
		if int(n) > len(b.b) {
			return 0, errors.New("truncated string data")
		}
		b.b = b.b[n:]
	}
	var flags uint64
	if !b.uint64(&flags) {
		return 0, errors.New("truncated flags")
	}
	return flags, nil
}

func TestHandleGetTokenInfo(t *testing.T) {
	tests := []struct {
		name      string
		slot      Slot
		wantFlags uint64
		wantLabel string
	}{
		{"InitializedToken", Slot{ID: 0x01, Label: "example", Initialized: true}, 0x00000400, "example"},
		{"UninitializedToken", Slot{ID: 0x01}, 0x0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &handler{s: &Handler{Slots: []Slot{tt.slot}}}
			var b buffer
			b.addUint64(0x01)
			resp, err := h.handleGetTokenInfo(&body{call: callGetTokenInfo, signature: "u", buffer: newBuffer(b.bytes())})
			if err != nil {
				t.Fatalf("handleGetTokenInfo: %v", err)
			}
			flags, err := tokenInfoFlags(resp)
			if err != nil {
				t.Fatalf("decoding flags: %v", err)
			}
			if flags != tt.wantFlags {
				t.Errorf("token flags = 0x%x, want 0x%x", flags, tt.wantFlags)
			}
			if flags&0x00000002 != 0 {
				t.Errorf("CKF_WRITE_PROTECTED is advertised, but tokens are initializable")
			}
		})
	}
}

func TestInitTokenThenGetTokenInfo(t *testing.T) {
	h := &handler{s: &Handler{
		Slots: []Slot{{ID: 0x01, Label: "old-label"}},
	}}
	if _, err := h.handleInitToken(initTokenRequest(0x01, "so-pin", "new-label")); err != nil {
		t.Fatalf("handleInitToken: %v", err)
	}

	var b buffer
	b.addUint64(0x01)
	resp, err := h.handleGetTokenInfo(&body{call: callGetTokenInfo, signature: "u", buffer: newBuffer(b.bytes())})
	if err != nil {
		t.Fatalf("handleGetTokenInfo: %v", err)
	}

	// The label is the first fixed-width string in the response.
	var labelLen uint32
	rb := newBuffer(resp.buffer.bytes())
	if !rb.uint32(&labelLen) || labelLen != 32 {
		t.Fatalf("label length = %d, want 32", labelLen)
	}
	if got := strings.TrimRight(string(rb.bytes()[:32]), " "); got != "new-label" {
		t.Errorf("token label = %q, want %q", got, "new-label")
	}

	flags, err := tokenInfoFlags(resp)
	if err != nil {
		t.Fatalf("decoding flags: %v", err)
	}
	if flags != 0x00000400 {
		t.Errorf("token flags = 0x%x, want 0x%x (CKF_TOKEN_INITIALIZED)", flags, 0x00000400)
	}
}
