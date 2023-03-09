package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func parsePort(str string) int {
	port, err := strconv.Atoi(str)
	if err != nil {
		panic(err)
	}
	return port
}

func main() {
	args := os.Args

	if len(args) < 6 {
		println(`./callDockerProxy "/snap/docker/2746/bin/docker-proxy" 0.0.0.0 9000 172.17.0.2 9000`)
		return
	}

	DockerProxyPath = args[1]

	if err := Proxy(args[2], parsePort(args[3]), args[4], parsePort(args[5])); err != nil {
		fmt.Printf("err.Error(): %v\n", err.Error())
	}

	for {
		time.Sleep(time.Second * 500)
	}
}
