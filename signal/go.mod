module github.com/meshnet/signal

go 1.25.0

require (
	github.com/meshnet/gen v0.0.0
	github.com/rs/zerolog v1.33.0
	google.golang.org/grpc v1.65.0
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240604185151-ef581f913117 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)

replace github.com/meshnet/gen => ../gen
