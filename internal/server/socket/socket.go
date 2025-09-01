package socket

import (
	"encoding/json"
)

type messageJSON struct {
	Type       string  `json:"type,omitempty"`
	Message    string  `json:"message,omitempty"`
	Val        float64 `json:"val,omitempty"`
	Txt        string  `json:"txt,omitempty"`
	Host       string  `json:"host,omitempty"`
	Scriptname string  `json:"scriptname,omitempty"`
}

// Legacy unprotected channel removed; use BroadcastSecure from secure.go
func Broadcast(msg string) { BroadcastSecure(msg) }

func Deploy(fileloc string) {
	bytes, _ := json.Marshal(messageJSON{Type: "deploy", Scriptname: fileloc[1:]}) // remove . at beginning
	Broadcast(string(bytes))
}

// Legacy Serve() removed
