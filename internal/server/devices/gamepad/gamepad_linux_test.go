//go:build (local || full) && linux

package gamepad

import (
	"testing"

	"github.com/holoplot/go-evdev"
)

func TestButtonMapping(t *testing.T) {
	// Test that our button mappings include all expected buttons
	expectedButtons := []evdev.EvCode{
		evdev.BTN_A,
		evdev.BTN_B,
		evdev.BTN_X,
		evdev.BTN_Y,
		evdev.BTN_TL,
		evdev.BTN_TR,
		evdev.BTN_SELECT,
		evdev.BTN_START,
		evdev.BTN_THUMBL,
		evdev.BTN_THUMBR,
		evdev.BTN_DPAD_UP,
		evdev.BTN_DPAD_DOWN,
		evdev.BTN_DPAD_LEFT,
		evdev.BTN_DPAD_RIGHT,
	}

	for _, btn := range expectedButtons {
		if _, exists := buttonMap[btn]; !exists {
			if _, exists := altButtonMap[btn]; !exists {
				t.Errorf("Button %d not found in button mappings", btn)
			}
		}
	}
}

func TestAxisValueConversion(t *testing.T) {
	tests := []struct {
		value    int32
		min      int32
		max      int32
		expected int16
	}{
		{0, -32768, 32767, 0},           // Center position
		{-32768, -32768, 32767, -32768}, // Minimum
		{32767, -32768, 32767, 32767},   // Maximum
		{16384, -32768, 32767, 16384},   // Half positive
		{-16384, -32768, 32767, -16384}, // Half negative
		{0, 0, 1023, -32768},            // Different range - min maps to minimum
		{1023, 0, 1023, 32767},          // Different range - max maps to maximum
		{512, 0, 1023, 32},              // Different range - middle maps to small positive
	}

	for _, test := range tests {
		result := convertAxisValue(test.value, test.min, test.max)
		if result != test.expected {
			t.Errorf("convertAxisValue(%d, %d, %d) = %d, want %d",
				test.value, test.min, test.max, result, test.expected)
		}
	}
}

func TestTriggerValueConversion(t *testing.T) {
	tests := []struct {
		value    int32
		min      int32
		max      int32
		expected uint8
	}{
		{0, 0, 255, 0},       // Not pressed
		{255, 0, 255, 255},   // Fully pressed
		{127, 0, 255, 127},   // Half pressed
		{0, 0, 1023, 0},      // Different range - not pressed
		{1023, 0, 1023, 255}, // Different range - fully pressed
	}

	for _, test := range tests {
		result := convertTriggerValue(test.value, test.min, test.max)
		if result != test.expected {
			t.Errorf("convertTriggerValue(%d, %d, %d) = %d, want %d",
				test.value, test.min, test.max, result, test.expected)
		}
	}
}

func TestGamepadDataEquality(t *testing.T) {
	data1 := gamepadData{
		button_mask:   0x1000,
		left_trigger:  128,
		right_trigger: 255,
		left_x:        -1000,
		left_y:        2000,
		right_x:       0,
		right_y:       -500,
	}

	data2 := gamepadData{
		button_mask:   0x1000,
		left_trigger:  128,
		right_trigger: 255,
		left_x:        -1000,
		left_y:        2000,
		right_x:       0,
		right_y:       -500,
	}

	data3 := gamepadData{
		button_mask:   0x2000, // Different button
		left_trigger:  128,
		right_trigger: 255,
		left_x:        -1000,
		left_y:        2000,
		right_x:       0,
		right_y:       -500,
	}

	// Test that identical data is considered equal
	if data1 != data2 {
		t.Error("Expected identical gamepad data to be equal")
	}

	// Test that different data is not equal
	if data1 == data3 {
		t.Error("Expected different gamepad data to not be equal")
	}
}

func TestAddPostJSON(t *testing.T) {
	data := gamepadData{
		button_mask:   0x1000,
		left_trigger:  128,
		right_trigger: 255,
		left_x:        -1000,
		left_y:        2000,
		right_x:       0,
		right_y:       -500,
	}

	var json gamepadJSON
	addPostJSON(&data, 2, &json)

	if json.Id != 2 {
		t.Errorf("Expected ID 2, got %d", json.Id)
	}

	if json.Drop {
		t.Error("Expected Drop to be false for valid gamepad data")
	}

	if json.Mask != 0x1000 {
		t.Errorf("Expected Mask 0x1000, got 0x%x", json.Mask)
	}

	if json.Ltrigger != 128 {
		t.Errorf("Expected Ltrigger 128, got %d", json.Ltrigger)
	}

	if json.Rtrigger != 255 {
		t.Errorf("Expected Rtrigger 255, got %d", json.Rtrigger)
	}

	if json.Lx != -1000 {
		t.Errorf("Expected Lx -1000, got %d", json.Lx)
	}

	if json.Ly != 2000 {
		t.Errorf("Expected Ly 2000, got %d", json.Ly)
	}

	if json.Rx != 0 {
		t.Errorf("Expected Rx 0, got %d", json.Rx)
	}

	if json.Ry != -500 {
		t.Errorf("Expected Ry -500, got %d", json.Ry)
	}
}

func TestAddPostJSONDrop(t *testing.T) {
	var json gamepadJSON
	addPostJSON(nil, 1, &json)

	if json.Id != 1 {
		t.Errorf("Expected ID 1, got %d", json.Id)
	}

	if !json.Drop {
		t.Error("Expected Drop to be true for nil gamepad data")
	}

	// All other fields should be zero/false for dropped gamepad
	if json.Mask != 0 {
		t.Errorf("Expected Mask 0 for dropped gamepad, got 0x%x", json.Mask)
	}
}

func TestButtonMaskOperations(t *testing.T) {
	var mask uint16 = 0

	// Test setting bits
	mask |= 0x1000 // A button
	mask |= 0x2000 // B button

	if mask != 0x3000 {
		t.Errorf("Expected mask 0x3000, got 0x%x", mask)
	}

	// Test checking bits
	if (mask & 0x1000) == 0 {
		t.Error("Expected A button to be set")
	}

	if (mask & 0x2000) == 0 {
		t.Error("Expected B button to be set")
	}

	if (mask & 0x4000) != 0 {
		t.Error("Expected X button to not be set")
	}

	// Test clearing bits
	mask &= ^uint16(0x1000) // Clear A button

	if mask != 0x2000 {
		t.Errorf("Expected mask 0x2000 after clearing A, got 0x%x", mask)
	}

	if (mask & 0x1000) != 0 {
		t.Error("Expected A button to be cleared")
	}

	if (mask & 0x2000) == 0 {
		t.Error("Expected B button to still be set")
	}
}

func TestGamepadConstants(t *testing.T) {
	if MAX_GAMEPADS != 4 {
		t.Errorf("Expected MAX_GAMEPADS to be 4, got %d", MAX_GAMEPADS)
	}

	if INPUT_DIR != "/dev/input" {
		t.Errorf("Expected INPUT_DIR to be '/dev/input', got '%s'", INPUT_DIR)
	}
}

func BenchmarkConvertAxisValue(b *testing.B) {
	for i := 0; i < b.N; i++ {
		convertAxisValue(16384, -32768, 32767)
	}
}

func BenchmarkConvertTriggerValue(b *testing.B) {
	for i := 0; i < b.N; i++ {
		convertTriggerValue(512, 0, 1023)
	}
}

func BenchmarkButtonMaskOperations(b *testing.B) {
	var mask uint16 = 0
	for i := 0; i < b.N; i++ {
		mask |= 0x1000
		mask &= ^uint16(0x1000)
	}
}
