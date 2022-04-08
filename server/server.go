package server

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// This struct is used to cast the fucntion for a specific
// channel (by Listen function) and then that function will
// access and executed by the handler function.
type handlerData struct {
	_listenChannel chan []byte
	_listenList    map[string]func(Transport, func(string, string, string) (int, error), []string)
}

// This struct is used to setting up some paramenters.
// Saddress : It is the ipv4 address on which  Server
//  and Engine will communicate. Default = 127.0.0.1
// Sport : It is the port on whixh Server and Engine
// 	will communicate Default = 7890
// Stimeout : maximum time for which server will try
// 	to 	connect to 	Engine before throwing Engine is
// 	unreachable or offline error
// MaxConnection : Give a integer value for how much
// 	concurrent connections do you wants.
// Channels : a slice of string containing channels on
//  which you want to operate
// Hstruct : This is for internal uses. User don't need
// 	to provide anything to it
type Server struct {
	Eaddress      string
	Eport         string
	Saddress      string
	Sport         string
	Stimeout      int
	MaxConnection int
	Channels      []string
	Hstruct       *handlerData
}

// This struct will be returned by the start()
// fucntion. It conatins some keys, hashes and
// con which is net.Conn object used to read and
// write data to the Engine.
type MAIN struct {
	nodeName      string
	nodeAesKey    []byte
	nodeRsaPriKey *rsa.PrivateKey
	nodeRsaPubKey *rsa.PublicKey
	server        *Server
	hash          string
	preHash       string
	con           net.Conn
	isAllSetup    bool
	CCDB          map[string]int
}

// Used to send and receive data from Engine.
// Name : Name of targat provided by the Engine
// Datetime : Date and time at the moment of execution
// Data : The actual data that you want send or receive
// Channel : channel on which send or receive will happen
type Transport struct {
	Type     string `json:"tp"`
	Name     string `json:"nm"`
	DateTime string `json:"dttm"`
	Data     string `json:"dt"`
	Channel  string `json:"chnl"`
}

type parent struct {
	TP string `json:"tp"`
	MD string `json:"md"`
	CJ string `json:"cj"`
}

type authStep1 struct {
	SPUBK string `json:"spubk"`
	SN    []byte `json:"sn"`
	HS    []byte `json:"hs"`
}

type authStep2 struct {
	ID   string `json:"id"`
	AESK []byte `json:"aesk"`
	CM   []byte `json:"cm"`
}

type authStep3 struct {
	CM []byte `json:"cm"`
	HS []byte `json:"hs"`
	SN []byte `json:"sn"`
}

type authStep4 struct {
	HS string `json:"hs"`
}

// type ListeningFunc func(Transport, func(string, string, string), []string)

// This type is used to register the function in Listen function
// i.e., If you want to register a function in the Listen function then your
// function should be of type Func
type Func func(Transport, func(string, string, string) (int, error), []string)

// Sets default value if not provided by the user
func (s *Server) defaultSetter() {

	if s.Eaddress == "" {
		s.Eaddress = "127.0.0.1"
	}
	if s.Eport == "" {
		s.Eport = "8080"
	}

	if s.Saddress == "" {
		s.Saddress = "127.0.0.1"
	}
	if s.Sport == "" {
		s.Sport = "7890"
	}
	if s.Stimeout == 0 {
		s.Stimeout = 1
	}
	if s.MaxConnection == 0 || s.MaxConnection < 100000 {
		s.MaxConnection = 100000
	}
	if len(s.Channels) == 0 {
		s.Channels = []string{}
		s.Channels = append(s.Channels, "main")
	}
	var Handler handlerData
	Handler._listenList = make(map[string]func(Transport, func(string, string, string) (int, error), []string))
	Handler._listenChannel = make(chan []byte)
	s.Hstruct = &Handler
}

// create a connection with engine and athenticate it by sharing key.
func connectToEngine(sMain *MAIN) {
	fmt.Println("Address: ", sMain.server.Saddress+":"+sMain.server.Sport)
	con, err := net.Dial("tcp", sMain.server.Saddress+":"+sMain.server.Sport)
	if err != nil {
		fmt.Println(err)
		return
	}
	sMain.isAllSetup = false
	sMain.upgradedAuthenticator(con)
}

// Used to initialise the server. It calls all the  internal functions
// and utilities needed for initilisation of server.
// Parameters:
// 		engine (string)   : location of the engine, if you want server
// 			  handles all the work of starting the Engine. If you want
// 			  to run the Engine  on another  Machine or  manually then
// 			  just pass "remote".
// 		address (string): If running Engine manually then just pass the
// 			  empty string, becouse you have already provided a address
// 			  to the Engine If server handles the Engine then pass the
// 			  IP address that your clients connect to.
// 		port (string)   : If running Engine manually then just pass the
// 			  empty string, becouse you have already provided a port to
// 			  the Engine If server handles the Engine then pass the port
// 			  that your clients connect to.
// Example:
// 		Manually: start("remote", "", "")
// 		Automatically: start("./shiSock", "1270.0.0.1", "8080")
func (s *Server) Start(engineLoc string) MAIN {

	// setting deafult value if not provided by the user
	// var setter Server
	s.defaultSetter()

	if engineLoc != "remote" {
		cmd := exec.Command(engineLoc, "--start", s.Eaddress, s.Eport, s.Saddress, s.Sport, strconv.Itoa(s.MaxConnection), " --ep")
		err := cmd.Start()
		handleError(err, "Error while Starting the engine")
	}

	// creating a internal record struct
	var sMain MAIN
	sMain.server = s
	sMain.CCDB = make(map[string]int)

	// connecting with engine
	connectToEngine(&sMain)

	go sMain.handler()
	return sMain
}

// Authenticate the Server and create a secured connection with Engine.
func (m *MAIN) upgradedAuthenticator(conn net.Conn) {

	privateKey, err := generateRsaPrivateKey(3000)
	handleError(err, "")
	publicKey := generateRsaPublicKey(privateKey)

	dumpedPublicKey, err := dumpKey(&publicKey)
	handleError(err, "")
	encodedDumpedPubliKey := encode(dumpedPublicKey)

	msg := generateAesKey(20)
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	handleError(err, "")
	msgHashSum := msgHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		panic(err)
	}

	var sOneChild authStep1
	sOneChild.HS = msgHashSum
	sOneChild.SN = signature
	sOneChild.SPUBK = encodedDumpedPubliKey

	sOneChildJson, err_ := json.Marshal(sOneChild)
	handleError(err_, "")
	var encodedsOneChildJson string = encode(sOneChildJson)

	var sOneMain parent
	sOneMain.TP = "auth-step-1"
	sOneMain.MD = "~~"
	sOneMain.CJ = encodedsOneChildJson

	sOneMainJson, er_r := json.Marshal(sOneMain)
	handleError(er_r, "")
	encodedsOneChildJson = encode(sOneMainJson)

	_, e := conn.Write([]byte(encodedsOneChildJson + "\n"))
	handleError(e, "")

	// Step 1 Comleted

	sTwo, err := bufio.NewReader(conn).ReadBytes('\n')
	handleError(err, "")

	var decodedsTwo []byte = decode(string(sTwo))

	var sTwoMain parent
	err = json.Unmarshal(decodedsTwo, &sTwoMain)
	handleError(err, "")

	if sTwoMain.TP == "auth-step-2" && sTwoMain.MD == "~~" {
		var ciphersTwoChild []byte = decode(sTwoMain.CJ)
		plainsTwoChild, e_r := rsaDecrypt(*privateKey, ciphersTwoChild)
		handleError(e_r, "")

		var sTwoChild authStep2
		err = json.Unmarshal(plainsTwoChild, &sTwoChild)
		handleError(err, "")

		msgHash_S2 := sha256.New()
		_, err = msgHash.Write(sTwoChild.CM)
		handleError(err, "")

		msgHashSum_S2 := msgHash_S2.Sum(nil)

		signature_S2, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum_S2, nil)
		if err != nil {
			panic(err)
		}

		confirmation_S2 := generateAesKey(20)

		var sThreeChild authStep3
		sThreeChild.CM = confirmation_S2
		sThreeChild.HS = msgHashSum_S2
		sThreeChild.SN = signature_S2

		sThreeChildJson, err_r := json.Marshal(sThreeChild)
		handleError(err_r, "")

		sThreeChildJsonCipher, errr := aesEncryption(sTwoChild.AESK, sThreeChildJson)
		handleError(errr, "")

		var encodedsTCJC string = encode(sThreeChildJsonCipher)

		var sThreeMain parent
		sThreeMain.TP = "auth-step-3"
		sThreeMain.MD = "~~"
		sThreeMain.CJ = encodedsTCJC

		sThreeMainJson, e := json.Marshal(sThreeMain)
		handleError(e, "")
		var encodedsThreeMainJson string = encode(sThreeMainJson)

		_, err_ := conn.Write([]byte(encodedsThreeMainJson + "\n"))
		handleError(err_, "")

		// ----------===============================Step 2 and 3 are completed ==========---------

		res_S4, err := bufio.NewReader(conn).ReadBytes('\n')
		handleError(err, "")

		decodedRes_S4 := decode(string(res_S4))

		var sFourMain parent

		e_r_ := json.Unmarshal(decodedRes_S4, &sFourMain)
		handleError(e_r_, "")

		if sFourMain.TP == "auth-step-4" && sFourMain.MD == "~~" {
			var cipherSFourChild []byte = decode(sFourMain.CJ)
			plainsFourChild, errr_ := aesDecryption(sTwoChild.AESK, cipherSFourChild)
			handleError(errr_, "")

			var sFourChild authStep4

			e_ := json.Unmarshal(plainsFourChild, &sFourChild)
			handleError(e_, "")

			h := sha256.New()
			h.Write(confirmation_S2)
			encodedStr := encode(h.Sum(nil))

			if string(sFourChild.HS) == encodedStr {
				m.nodeAesKey = sTwoChild.AESK
				m.hash = sFourChild.HS
				m.nodeName = sTwoChild.ID
				m.preHash = ""
				m.nodeRsaPriKey = privateKey
				m.nodeRsaPubKey = &publicKey
				m.isAllSetup = true

			} else {
				panic("authentication failed. Something bad happen")
			}

			m.con = conn
		}
	}
}

// Listen for the data that is comming from the Engine
// It works in a way that it takes three arguments, channle, fn, args.
// Most important is fn, the function (should be of type Func), It will
// every time it reads new data from Engine.
// Parameters:
// 		channel (string) : channel on which it will read the data
// 		fn (Func) : fn is function of type Func which will treger
// 			every time a new data is read.
// 		args ([]string) : optional argument for the fn function,
// 			if no argument is needed it should be nil.
func (m *MAIN) Listen(channel string, fn Func, args []string) {

	m.server.Hstruct._listenList[channel] = fn
}

// It start the server and it should be called at end of the program
// means it should be called when you are assured that all the pre-
// requirements are being setup and server is ready to run.
// It is blocking in nature that means it will force the server
// to run forever.
func (m *MAIN) Run() {
	fmt.Println("[ Process ID: ", os.Getpid(), " ]")
	fmt.Println("shiSock engine is Started on: {", m.server.Saddress, ":", m.server.Sport, "}")

	for {

	}
}

// Authenticate the Server and create a secured connection with Engine.

// Sends data to the client using the client name and channel
// Parameter:
// 	 	name (string)   : name of targeted client name given by the Engine.
//   	channel (string): channel on which you want this data is being listen or read.
// 		data (string)   : Data that you want to send.
func (m *MAIN) Send(name string, channel string, data string) (int, error) {

	if len(data) >= 1 {

		var res Transport
		res.Type = "E-DSP"
		res.Channel = channel
		res.Name = name
		res.Data = data
		res.DateTime = time.Now().String()

		jsonres, err := json.Marshal(&res)
		handleError(err, "")
		cipherText, e_rr := aesEncryption(m.nodeAesKey, jsonres)
		handleError(e_rr, "")
		encodedCipherText := encode(cipherText)

		var sendMain parent
		sendMain.TP = "auth-E-DSP"
		sendMain.MD = "~~"
		sendMain.CJ = encodedCipherText

		sendMainJson, err := json.Marshal(sendMain)
		handleError(err, "")

		var encodedSendMainJson string = encode(sendMainJson)

		encodedSendMainJsonLen := strconv.Itoa(len(encodedSendMainJson))

		encodedCipherText = encodedSendMainJson + "." + encodedSendMainJsonLen + "." + "~|||~"
		n, err_ := m.con.Write([]byte(encodedCipherText + "\n"))
		fmt.Println("send response to client... | ", n)
		return n, err_

	} else {
		return -1, errors.New("message is too small to send")
	}
}

func (m *MAIN) Close(name string) {
	// function for closing the connection between client and engine
	var res Transport
	res.Type = "ECC-CLOSE"
	res.Channel = "INTERNAL"
	res.Name = name
	res.Data = "close the engine and client connection"
	res.DateTime = time.Now().String()

	jsonres, err := json.Marshal(&res)
	handleError(err, "")
	cipherText, e_rr := aesEncryption(m.nodeAesKey, jsonres)
	handleError(e_rr, "")
	encodedCipherText := encode(cipherText)

	var sendMain parent
	sendMain.TP = "INTERNAL"
	sendMain.MD = "~~"
	sendMain.CJ = encodedCipherText

	sendMainJson, err := json.Marshal(sendMain)
	handleError(err, "")

	var encodedSendMainJson string = encode(sendMainJson)

	encodedSendMainJsonLen := strconv.Itoa(len(encodedSendMainJson))

	encodedCipherText = encodedSendMainJson + "." + encodedSendMainJsonLen + "." + "~|||~"
	_, err_ := m.con.Write([]byte(encodedCipherText + "\n"))
	handleError(err_, "Error while sending the close request to the Engine")
}

func (m *MAIN) IsClosed(name string) int {
	// function for checking whether that the connection between the client and engine has been closed.
	var n int = m.CCDB[name]
	if n == 1 {
		return 1
	} else if n == 0 {
		return -1
	} else {
		return 0
	}
}

// Reads data that is comming from Engine.
// This function works along with the Listen fucntion.
func (m *MAIN) handler() {

	for {
		if m.isAllSetup {
			for {
				data, err := bufio.NewReader(m.con).ReadBytes('\n')
				handleError(err, "Error while reading data from engine: ")

				data = data[0 : len(data)-1]

				decodedData := decode(string(data))

				var recvMain parent
				er := json.Unmarshal(decodedData, &recvMain)
				handleError(er, "Error while Unmarshaling data from engine: ")

				if recvMain.TP == "auth-E-DSP" && recvMain.MD == "~~" {
					var recvChildCipherText []byte = decode(recvMain.CJ)
					recvChildJson, e := aesDecryption(m.nodeAesKey, recvChildCipherText)
					handleError(e, "")

					var recvChild Transport
					e_rr := json.Unmarshal(recvChildJson, &recvChild)
					handleError(e_rr, "")

					if recvChild.Type == "E-DSP" {
						if m.server.Hstruct._listenList[recvChild.Channel] != nil {
							Caller := m.server.Hstruct._listenList[recvChild.Channel]
							Caller(recvChild, m.Send, []string{"one", "two"})
						}
					}

				} else if recvMain.TP == "INTERNAL" && recvMain.MD == "~~" {
					var recvChildCipherText []byte = decode(recvMain.CJ)
					recvChildJson, e := aesDecryption(m.nodeAesKey, recvChildCipherText)
					handleError(e, "")

					var recvChild Transport
					e_rr := json.Unmarshal(recvChildJson, &recvChild)
					handleError(e_rr, "")

					if recvChild.Type == "CC" && recvChild.Data == "closedConnectionWithClient" {
						m.CCDB[recvChild.Name] = 1
					}
				}
			}
		}
	}
}
