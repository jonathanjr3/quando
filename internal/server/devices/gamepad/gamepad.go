//go:build (local || full) && !windows && !linux

package gamepad

import "fmt"

func CheckChanged() {
	fmt.Println("** Gamepad support not available on this platform")
	return
}
