module github.com/blinex/signal

go 1.25.0

toolchain go1.25.12

require (
	github.com/blinex/gen v0.0.0
	github.com/rs/zerolog v1.33.0
	google.golang.org/grpc v1.82.1
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/blinex/gen => ../gen
