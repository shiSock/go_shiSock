package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/shiSock/go_shiSock/client"
)

func test(trans client.Transport, sender func(string, string) (int, error), args []string) {
	fmt.Println("New Message...")
	fmt.Println("trans: ", trans)
	fmt.Println("args: ", args)
}

func main() {
	fmt.Println("Welcome to goshiSock client")
	var sock client.Client
	main := sock.Start("127.0.0.1", "8080")
	main.Listen("main", test, []string{"one", "two"})

	for {
		fmt.Println("Write Text: ")
		data, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			panic(err)
		}

		main.Send("main", data)

	}
}
