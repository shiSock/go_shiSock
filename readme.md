# goshiSock

### Golang utility for shiSock Engine

This utility can be used to interacte with shiSock Engine. This package comes with both server and client utility.

## Usage:
Installation : From the root directory of project run 
`go get github.com/shiSock/goshiSock`

### Server Example

server.go

```golang
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


```

### Client Example

client.go

```golang
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

```