package main

import (
	"fmt"
	"quando/internal/config"
	"quando/internal/server"
	"quando/internal/server/ip"
	"quando/internal/tray"
)

var handlers = []server.Handler{} // extra handlers are added when full version has been built, e.g. using build_full.bat

func main() {
	fmt.Println("Quando Go Server started")
	ipAddress := ip.PrivateIP()
	if config.Remote() {
		fmt.Println("**SECURITY WARNING** Quando can be accessed remotely at ", ipAddress)
	}

	// Run server in background goroutine
	go server.ServeHTTPandIO(handlers)

	// Run system tray on main thread (required by systray)
	tray.Run()
}
