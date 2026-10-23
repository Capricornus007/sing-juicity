module github.com/exclavenetwork/sing-juicity

go 1.28

retract (
	v0.2.0 // upstream sing-quic v0.6.4 has disappeared
	v0.1.0-beta.5
	v0.1.0-beta.4
)

require (
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.12
	github.com/sagernet/sing v0.9.7-0.20261022215834-56e8e9fb54a4
	github.com/sagernet/sing-quic v0.7.2-0.20261020082049-7e0a5869a5f4
)

require (
	github.com/andybalholm/brotli v1.2.6 // indirect
	github.com/klauspost/compress v1.20.3 // indirect
	github.com/metacubex/utls v1.8.8 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/sagernet/sing-quic => github.com/Capricornus007/sing-quic v0.7.0-beta.2.0.20261023034421-e8d980d7061e
