module github.com/myguard-labs/gozer

go 1.24

require (
	github.com/myguard-labs/gazor v1.1.0
	github.com/myguard-labs/gdcc v1.1.0
	github.com/myguard-labs/gyzor v1.1.0
	github.com/redis/go-redis/v9 v9.20.1
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/text v0.23.0 // indirect
)

// Versions v1.0.0–v1.1.0 were published under the old module path
// github.com/eilandert/gozer. Under the new path they are invalid.
retract (
	v1.1.0
	v1.0.0
)
