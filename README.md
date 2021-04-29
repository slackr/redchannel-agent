# RedChannel Implant

To be used by the RedChannel-C2 server to generate agent binaries. C2 will use the `config.go.sample` file to create the missing `config.go` with appropriate values for the campaign.

If building manually, place a custom `config.go` in `./config/` or builds will fail.

## Debug Builds

Build Windows Debug

`go build -a -v -x -o build/agent-debug.exe .`

Build Linux Debug

`env GOOS=linux GOARCH=amd64 go build -a -v -x -o build/agent-debug .`

## Production Builds

Build Windows x64

`env GOOS=windows GOARCH=amd64 go build -a -v -x -ldflags='-s -w' -o build/agent64.exe .`

Build Linux x64

`env GOOS=linux GOARCH=amd64 go build -a -v -x -ldflags='-s -w' -o build/agent64 .`

Build Windows x86

`env GOOS=windows GOARCH=386 go build -a -v -x -ldflags='-s -w' -o build/agent32.exe .`

Build Linux x86

`env GOOS=linux GOARCH=386 go build -a -v -x -ldflags='-s -w' -o build/agent32 .`

Build Linux ARM64

`env GOOS=linux GOARCH=arm64 go build -a -v -x -ldflags='-s -w' -o build/agent-arm64 .`
