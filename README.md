# RedChannel Implant

To be used by the RedChannel-C2 server to generate agent binaries. C2 will use the `config.go.sample` file to create a `config.go` with appropriate values for the campaign.

If building manually, place a custom `config.go` in `./config/` or builds will fail.

## Build using toolset

```bash
python tools/build.py . ./build/agent64.exe win amd64 [debug]
```

## garble tool install for obfuscation

```bash
go install mvdan.cc/garble@latest
```

## Debug Builds

Build Windows Debug

```bash
go build -a -v -x -o build/agent-debug.exe .
```

Build Linux Debug

```bash
env GOOS=linux GOARCH=amd64 go build -a -v -x -o build/agent-debug .
```

## Production Builds

Build Windows x64

```bash
env GOOS=windows GOARCH=amd64 go build -a -v -x -ldflags='-s -w' -o build/agent64.exe .
```

Build Linux x64

```bash
env GOOS=linux GOARCH=amd64 go build -a -v -x -ldflags='-s -w' -o build/agent64 .
```

Build Windows x86

```bash
env GOOS=windows GOARCH=386 go build -a -v -x -ldflags='-s -w' -o build/agent32.exe .
```

Build Linux x86

```bash
env GOOS=linux GOARCH=386 go build -a -v -x -ldflags='-s -w' -o build/agent32 .
```

Build Linux ARM64

```bash
env GOOS=linux GOARCH=arm64 go build -a -v -x -ldflags='-s -w' -o build/agent-arm64 .
```
