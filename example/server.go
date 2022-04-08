package main

import (
	"fmt"

	"github.com/shiSock/go_shiSock/server"
)

func test(trans server.Transport, Sender func(string, string, string) (int, error), args []string) {
	fmt.Println("trans: ", trans)
	fmt.Println("args: ", args)
	Sender(trans.Name, trans.Channel, trans.Data)
}

func main() {
	fmt.Println("Starting Server...")
	var sock server.Server
	sock.Saddress = "127.0.0.1"
	sock.Sport = "7890"

	sock.Eaddress = "127.0.0.1"
	sock.Eport = "8080"

	main := sock.Start("remote")
	main.Listen("main", test, []string{"one", "two"})

	main.Run()

}
