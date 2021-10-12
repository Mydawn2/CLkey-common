build:
	go build ./...

mockgen:
	cd msgbus && mockgen -destination ./mock/msg_bus_mock.go -package mock -source ./message_bus.go
ut:
	go test -cover ./...