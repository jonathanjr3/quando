//go:build local || full

package tray

import (
	"fmt"
	"os"
	"os/signal"
	"quando/internal/icon"
	"quando/internal/server"

	"fyne.io/systray"
	"github.com/skratchdot/open-golang/open"
)

func Run() {
	systray.Run(setup, close)
}

func setup() {
	fmt.Println("Setting up system tray...")

	// handle OS interrupt
	interrupt_channel := make(chan os.Signal, 1)
	signal.Notify(interrupt_channel, os.Interrupt)
	go handleInterrupt(interrupt_channel)

	// Check if we can set icon
	iconData := icon.Data()

	// setup menu
	systray.SetIcon(iconData)
	systray.SetTitle("Quando")
	systray.SetTooltip("Quando - noCode Toolset")

	sysEditor := systray.AddMenuItem("Editor", "Open Editor")
	sysClient := systray.AddMenuItem("Client", "Open Client")
	systray.AddSeparator()
	sysDashboard := systray.AddMenuItem("Dashboard", "Open Dashboard")
	systray.AddSeparator()
	sysGithub := systray.AddMenuItem("Quando:Github", "Open Quando -> Github")
	systray.AddSeparator()
	sysQuit := systray.AddMenuItem("Quit", "Stop the server")

	// Handle Clicks
	go func() {
		for {
			select {
			case <-sysQuit.ClickedCh:
				systray.Quit()
			case <-sysEditor.ClickedCh:
				openDefaultBrowser("/editor")
			case <-sysClient.ClickedCh:
				openDefaultBrowser("/join")
			case <-sysDashboard.ClickedCh:
				openDefaultBrowser("/admin")
			case <-sysGithub.ClickedCh:
				open.Start("https://github.com/jonathanjr3/quando")
			}
		}
	}()
}

func handleInterrupt(interrupt chan os.Signal) {
	<-interrupt
	fmt.Println("<<Interrupt>>")
	systray.Quit()
}

func openDefaultBrowser(suffix string) {
	url := "http://127.0.0.1" + server.Port() + suffix
	err := open.Start(url)
	if err != nil {
		fmt.Printf("Failed to open URL in default browser: %v\n", err)
	}
}

func close() {
	fmt.Println("Systray quit...shutting down server...")
	server.Quit()
}
