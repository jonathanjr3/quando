# Gamepad Support in Quando

This module provides gamepad support for the Quando visual programming system. It includes implementations for both Windows and Linux platforms.

## Platform Support

### Windows
- Uses XInput API via `xinput1_3.dll`
- Supports Xbox-compatible controllers
- Implemented in `gamepad_windows.go`

### Linux
- Uses evdev interface via `/dev/input/event*` devices
- Supports any gamepad that works with the Linux input subsystem
- Implemented in `gamepad_linux.go`

## Linux Setup

### Prerequisites
- Your user must be in the `input` group to access gamepad devices
- Add yourself to the group: `sudo usermod -a -G input $USER`
- Log out and log back in for the changes to take effect

### Supported Controllers
The Linux implementation supports any gamepad that:
- Exposes analog sticks (ABS_X, ABS_Y, ABS_RX, ABS_RY)
- Has standard gamepad buttons
- Is recognized by the Linux input subsystem

Common supported controllers include:
- Xbox One/Series controllers
- PlayStation DualShock/DualSense controllers
- Generic USB gamepads
- Bluetooth controllers

### Testing
You can test if your gamepad is detected by:
1. Running `ls /dev/input/event*` to see available input devices
2. Using `evtest` to test your specific gamepad
3. Checking the Quando logs for "Found gamepad" messages

## Button Mapping

The Linux implementation maps evdev button codes to match the Windows XInput format:

| Button | Linux evdev | Windows XInput |
|--------|-------------|----------------|
| A | BTN_A/BTN_SOUTH | 0x1000 |
| B | BTN_B/BTN_EAST | 0x2000 |
| X | BTN_X/BTN_NORTH | 0x4000 |
| Y | BTN_Y/BTN_WEST | 0x8000 |
| Left Bumper | BTN_TL | 0x0100 |
| Right Bumper | BTN_TR | 0x0200 |
| Back/Select | BTN_SELECT | 0x0020 |
| Start | BTN_START | 0x0010 |
| Left Stick | BTN_THUMBL | 0x0040 |
| Right Stick | BTN_THUMBR | 0x0080 |
| D-Pad Up | BTN_DPAD_UP | 0x0001 |
| D-Pad Down | BTN_DPAD_DOWN | 0x0002 |
| D-Pad Left | BTN_DPAD_LEFT | 0x0004 |
| D-Pad Right | BTN_DPAD_RIGHT | 0x0008 |

## Axis Mapping

| Axis | Linux evdev | Description |
|------|-------------|-------------|
| Left Stick X | ABS_X | Horizontal movement |
| Left Stick Y | ABS_Y | Vertical movement |
| Right Stick X | ABS_RX | Horizontal movement |
| Right Stick Y | ABS_RY | Vertical movement |
| Left Trigger | ABS_Z | Pressure sensitive |
| Right Trigger | ABS_RZ | Pressure sensitive |

## Architecture

The implementation follows an event-driven architecture:
1. Scans `/dev/input/event*` for gamepad devices
2. Opens detected devices in non-blocking mode
3. Continuously reads input events
4. Translates events to Windows XInput-compatible JSON format
5. Broadcasts changes via WebSocket to clients

## JSON Format

The gamepad data is sent to clients in the same JSON format as Windows:

```json
{
  "type": "gamepad",
  "id": 0,
  "mask": 4096,
  "l_trigger": 0,
  "r_trigger": 0,
  "l_x": 0,
  "l_y": 0,
  "r_x": 0,
  "r_y": 0
}
```

## Troubleshooting

### Permission Denied
- Ensure your user is in the `input` group
- Check device permissions: `ls -l /dev/input/event*`
- Try running as root temporarily to test

### Gamepad Not Detected
- Check if the device appears in `/dev/input/`
- Use `evtest` to verify the device works
- Ensure the gamepad has both analog sticks and buttons

### Performance Issues
- The implementation uses non-blocking I/O for efficiency
- Events are processed at 60Hz like the Windows version
- Device scanning occurs every second

## Development

To add support for additional button mappings or axis types:
1. Add the evdev constants to `buttonMap` or handle in `processGamepadEvent`
2. Map to the appropriate Windows XInput bit mask
3. Test with your specific controller