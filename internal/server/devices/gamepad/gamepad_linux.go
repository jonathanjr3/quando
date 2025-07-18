//go:build (local || full) && linux

package gamepad

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"quando/internal/server/socket"
	"strings"
	"time"

	"github.com/holoplot/go-evdev"
)

// Linux gamepad implementation using the evdev interface
// This provides gamepad support on Linux systems by reading from /dev/input/event* devices
// and translating Linux input events to the same JSON format as the Windows XInput implementation

const (
	MAX_GAMEPADS = 4
	INPUT_DIR    = "/dev/input"
)

type linuxGamepad struct {
	device   *evdev.InputDevice
	id       int
	name     string
	lastData gamepadData
}

type gamepadData struct {
	button_mask   uint16
	left_trigger  uint8
	right_trigger uint8
	left_x        int16
	left_y        int16
	right_x       int16
	right_y       int16
}

var gamepads [MAX_GAMEPADS]*linuxGamepad

type gamepadJSON struct {
	Id       int8   `json:"id"`
	Drop     bool   `json:"drop,omitempty"`
	Mask     uint16 `json:"mask,omitempty"`
	Ltrigger uint8  `json:"l_trigger,omitempty"`
	Rtrigger uint8  `json:"r_trigger,omitempty"`
	Lx       int16  `json:"l_x,omitempty"`
	Ly       int16  `json:"l_y,omitempty"`
	Rx       int16  `json:"r_x,omitempty"`
	Ry       int16  `json:"r_y,omitempty"`
}

// Button mapping to match Windows XInput format
var buttonMap = map[evdev.EvCode]uint16{
	evdev.BTN_A:      0x1000, // A
	evdev.BTN_B:      0x2000, // B
	evdev.BTN_X:      0x4000, // X
	evdev.BTN_Y:      0x8000, // Y
	evdev.BTN_TL:     0x0100, // L_BUMPER
	evdev.BTN_TR:     0x0200, // R_BUMPER
	evdev.BTN_SELECT: 0x0020, // BACK
	evdev.BTN_START:  0x0010, // START
	evdev.BTN_THUMBL: 0x0040, // L_STICK
	evdev.BTN_THUMBR: 0x0080, // R_STICK
	// D-pad
	evdev.BTN_DPAD_UP:    0x0001, // UP
	evdev.BTN_DPAD_DOWN:  0x0002, // DOWN
	evdev.BTN_DPAD_LEFT:  0x0004, // LEFT
	evdev.BTN_DPAD_RIGHT: 0x0008, // RIGHT
}

// Alternative button mappings for different gamepad types
var altButtonMap = map[evdev.EvCode]uint16{
	evdev.BTN_SOUTH: 0x1000, // A (PlayStation Cross)
	evdev.BTN_EAST:  0x2000, // B (PlayStation Circle)
	evdev.BTN_WEST:  0x4000, // X (PlayStation Square)
	evdev.BTN_NORTH: 0x8000, // Y (PlayStation Triangle)
}

func isGamepadDevice(device *evdev.InputDevice) bool {
	// Check if device has joystick capabilities
	capableTypes := device.CapableTypes()

	hasAbs := false
	hasKey := false

	for _, evType := range capableTypes {
		if evType == evdev.EV_ABS {
			hasAbs = true
		}
		if evType == evdev.EV_KEY {
			hasKey = true
		}
	}

	if !hasAbs || !hasKey {
		return false
	}

	// Check for analog sticks
	absEvents := device.CapableEvents(evdev.EV_ABS)
	hasStick := false
	for _, abs := range absEvents {
		if abs == evdev.ABS_X || abs == evdev.ABS_Y ||
			abs == evdev.ABS_RX || abs == evdev.ABS_RY {
			hasStick = true
			break
		}
	}

	if !hasStick {
		return false
	}

	// Check if device has gamepad buttons
	keyEvents := device.CapableEvents(evdev.EV_KEY)
	hasButtons := false
	for _, key := range keyEvents {
		if _, exists := buttonMap[key]; exists {
			hasButtons = true
			break
		}
		if _, exists := altButtonMap[key]; exists {
			hasButtons = true
			break
		}
	}

	return hasButtons
}

func findGamepadDevices() []*evdev.InputDevice {
	var devices []*evdev.InputDevice

	files, err := os.ReadDir(INPUT_DIR)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", INPUT_DIR, err)
		return devices
	}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), "event") {
			devicePath := filepath.Join(INPUT_DIR, file.Name())

			device, err := evdev.Open(devicePath)
			if err != nil {
				// Skip devices we can't open (common for permission issues)
				continue
			}

			if isGamepadDevice(device) {
				devices = append(devices, device)
				name, err := device.Name()
				if err != nil {
					name = "Unknown"
				}
				fmt.Printf("Found gamepad: %s at %s\n", name, devicePath)
			} else {
				device.Close()
			}
		}
	}

	/*if len(devices) == 0 {
		// Only log this occasionally to avoid spam
		fmt.Println("No gamepad devices found. Make sure your user is in the 'input' group.")
	}*/

	return devices
}

func convertAxisValue(value int32, min, max int32) int16 {
	// Convert to range similar to Windows XInput (-32768 to 32767)
	if max == min {
		return 0
	}

	// Handle the special case where the range is already -32768 to 32767
	if min == -32768 && max == 32767 {
		// Direct conversion, but handle the asymmetric range
		if value == -32768 {
			return -32768
		}
		return int16(value)
	}

	// Normalize to -1.0 to 1.0, then scale to int16 range
	normalized := float64(value-min) / float64(max-min) // 0 to 1
	normalized = (normalized * 2.0) - 1.0               // -1 to 1

	// Scale to full int16 range, handling asymmetric range
	if normalized < 0 {
		return int16(normalized * 32768.0)
	}
	return int16(normalized * 32767.0)
}

func convertTriggerValue(value int32, min, max int32) uint8 {
	// Convert to 0-255 range like Windows XInput
	if max == min {
		return 0
	}

	normalized := float64(value-min) / float64(max-min) // 0 to 1
	return uint8(normalized * 255.0)
}

func processGamepadEvent(gp *linuxGamepad, event *evdev.InputEvent) bool {
	if gp.device == nil {
		return false
	}

	changed := false

	switch event.Type {
	case evdev.EV_KEY:
		// Handle button events
		if mask, exists := buttonMap[event.Code]; exists {
			if event.Value > 0 {
				// Button pressed
				if (gp.lastData.button_mask & mask) == 0 {
					gp.lastData.button_mask |= mask
					changed = true
				}
			} else {
				// Button released
				if (gp.lastData.button_mask & mask) != 0 {
					gp.lastData.button_mask &= ^mask
					changed = true
				}
			}
		} else if mask, exists := altButtonMap[event.Code]; exists {
			if event.Value > 0 {
				// Button pressed
				if (gp.lastData.button_mask & mask) == 0 {
					gp.lastData.button_mask |= mask
					changed = true
				}
			} else {
				// Button released
				if (gp.lastData.button_mask & mask) != 0 {
					gp.lastData.button_mask &= ^mask
					changed = true
				}
			}
		}

	case evdev.EV_ABS:
		// Handle axis events
		var oldValue, newValue int16
		var oldTrigger, newTrigger uint8

		switch event.Code {
		case evdev.ABS_X:
			oldValue = gp.lastData.left_x
			absInfo, err := gp.device.AbsInfos()
			if err == nil {
				if info, exists := absInfo[event.Code]; exists {
					newValue = convertAxisValue(event.Value, info.Minimum, info.Maximum)
					if oldValue != newValue {
						gp.lastData.left_x = newValue
						changed = true
					}
				}
			}
		case evdev.ABS_Y:
			oldValue = gp.lastData.left_y
			absInfo, err := gp.device.AbsInfos()
			if err == nil {
				if info, exists := absInfo[event.Code]; exists {
					newValue = convertAxisValue(event.Value, info.Minimum, info.Maximum)
					if oldValue != newValue {
						gp.lastData.left_y = newValue
						changed = true
					}
				}
			}
		case evdev.ABS_RX:
			oldValue = gp.lastData.right_x
			absInfo, err := gp.device.AbsInfos()
			if err == nil {
				if info, exists := absInfo[event.Code]; exists {
					newValue = convertAxisValue(event.Value, info.Minimum, info.Maximum)
					if oldValue != newValue {
						gp.lastData.right_x = newValue
						changed = true
					}
				}
			}
		case evdev.ABS_RY:
			oldValue = gp.lastData.right_y
			absInfo, err := gp.device.AbsInfos()
			if err == nil {
				if info, exists := absInfo[event.Code]; exists {
					newValue = convertAxisValue(event.Value, info.Minimum, info.Maximum)
					if oldValue != newValue {
						gp.lastData.right_y = newValue
						changed = true
					}
				}
			}
		case evdev.ABS_Z:
			oldTrigger = gp.lastData.left_trigger
			absInfo, err := gp.device.AbsInfos()
			if err == nil {
				if info, exists := absInfo[event.Code]; exists {
					newTrigger = convertTriggerValue(event.Value, info.Minimum, info.Maximum)
					if oldTrigger != newTrigger {
						gp.lastData.left_trigger = newTrigger
						changed = true
					}
				}
			}
		case evdev.ABS_RZ:
			oldTrigger = gp.lastData.right_trigger
			absInfo, err := gp.device.AbsInfos()
			if err == nil {
				if info, exists := absInfo[event.Code]; exists {
					newTrigger = convertTriggerValue(event.Value, info.Minimum, info.Maximum)
					if oldTrigger != newTrigger {
						gp.lastData.right_trigger = newTrigger
						changed = true
					}
				}
			}
		}
	}

	return changed
}

func addGamepad(device *evdev.InputDevice) int {
	// Find empty slot
	for i := 0; i < MAX_GAMEPADS; i++ {
		if gamepads[i] == nil {
			name, err := device.Name()
			if err != nil {
				name = "Unknown"
			}
			gamepads[i] = &linuxGamepad{
				device: device,
				id:     i,
				name:   name,
			}
			fmt.Printf("Gamepad connected: %s (ID: %d)\n", name, i)
			return i
		}
	}

	// No empty slots
	device.Close()
	return -1
}

func removeGamepad(id int) {
	if id >= 0 && id < MAX_GAMEPADS && gamepads[id] != nil {
		if err := gamepads[id].device.Close(); err != nil {
			fmt.Printf("Warning: Error closing gamepad %d: %v\n", id, err)
		}
		gamepads[id] = nil
	}
}

func addPostJSON(data *gamepadData, id int, gamepad_json *gamepadJSON) {
	gamepad_json.Id = int8(id)
	if data == nil {
		gamepad_json.Drop = true
	} else {
		gamepad_json.Mask = data.button_mask
		gamepad_json.Ltrigger = data.left_trigger
		gamepad_json.Rtrigger = data.right_trigger
		gamepad_json.Lx = data.left_x
		gamepad_json.Ly = data.left_y
		gamepad_json.Rx = data.right_x
		gamepad_json.Ry = data.right_y
	}
}

func scanForNewGamepads() {
	devices := findGamepadDevices()

	// Check for new devices
	for _, device := range devices {
		isNew := true

		// Check if we already have this device
		for i := 0; i < MAX_GAMEPADS; i++ {
			if gamepads[i] != nil && gamepads[i].device.Path() == device.Path() {
				isNew = false
				break
			}
		}

		if isNew {
			id := addGamepad(device)
			if id == -1 {
				fmt.Printf("Warning: Maximum number of gamepads (%d) reached\n", MAX_GAMEPADS)
			}
		} else {
			device.Close() // Close duplicate
		}
	}
}

func CheckChanged() {
	fmt.Println("Starting Linux gamepad monitoring...")

	// Initial scan
	scanForNewGamepads()

	scanTicker := time.NewTicker(time.Second) // Scan for new devices every second
	defer scanTicker.Stop()

	for {
		select {
		case <-scanTicker.C:
			scanForNewGamepads()
		default:
			// Check for events in existing gamepads
			updated := false
			gamepad_json := gamepadJSON{}

			for i := 0; i < MAX_GAMEPADS; i++ {
				if gamepads[i] != nil {
					// Check if device is still accessible
					if _, err := os.Stat(gamepads[i].device.Path()); os.IsNotExist(err) {
						// Device disconnected
						fmt.Printf("Gamepad %d disconnected: %s\n", i, gamepads[i].name)
						removeGamepad(i)
						updated = true
						addPostJSON(nil, i, &gamepad_json)
					} else {
						// Set device to non-blocking mode
						if err := gamepads[i].device.NonBlock(); err != nil {
							fmt.Printf("Warning: Could not set gamepad %d to non-blocking mode: %v\n", i, err)
							continue
						}

						// Try to read events
						eventCount := 0
						for {
							event, err := gamepads[i].device.ReadOne()
							if err != nil {
								// No more events or error - this is normal for non-blocking read
								break
							}
							eventCount++
							if processGamepadEvent(gamepads[i], event) {
								updated = true
								addPostJSON(&gamepads[i].lastData, i, &gamepad_json)
							}
							// Limit events per iteration to prevent blocking
							if eventCount > 10 {
								break
							}
						}
					}
				}
			}

			if updated {
				bout, err := json.Marshal(gamepad_json)
				if err != nil {
					fmt.Printf("Error marshalling gamepad data: %v\n", err)
				} else {
					str := string(bout)
					prefix := `{"type":"gamepad"`
					if str != "{}" {
						prefix += ","
					}
					str = prefix + str[1:]
					socket.Broadcast(str)
				}
			}
		}

		time.Sleep(time.Second / 60) // 60 times a second
	}
}
