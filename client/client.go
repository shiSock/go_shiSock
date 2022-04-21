package client

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
	"strconv"
	"strings"
	"time"
)

// This struct is used to cast the fucntion for a specific
// channel (by Listen function) and then that function will
// access and executed by the handler function.
type handlerData struct {
	_listenChannel chan []byte
	_listenList    map[string]func(Transport, func(string, string) (int, error), []string)
}

// This struct is used to setting up some paramenters.
// Channels : a slice of string containing channels on
//  which you want to operate
// Hstruct : This is for internal uses. User don't need
// 	to provide anything to it
type Client struct {
	channels []string
	hstruct  *handlerData
}

// This struct will be returned by the start()
// fucntion. It contains some keys, hashes and
// con which is net.Conn object used to read and
// write data to the Engine.
type MAIN struct {
	clientName      string
	clientAesKey    []byte
	clientRsaPriKey *rsa.PrivateKey
	clientRsaPubKey *rsa.PublicKey
	client          *Client
	hash            []byte
	preHash         []byte
	con             net.Conn
	isAllSetup      bool
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

// This type is used to register the function in Listen function
// i.e., If you want to register a function in the Listen function then your
// function should be of type Func
type Func func(Transport, func(string, string) (int, error), []string)

// Sets default value if not provided by the user
func (c *Client) defaultSetter() {

	if len(c.channels) == 0 {
		c.channels = append(c.channels, "main")
	}

	var Handler handlerData
	Handler._listenList = make(map[string]func(Transport, func(string, string) (int, error), []string))
	Handler._listenChannel = make(chan []byte)
	c.hstruct = &Handler
}

func updatedsendData(data string, con net.Conn) (int, error) {
	if len(data) < 1024 {
		n, err := con.Write([]byte(data))
		if err != nil {
			return -1, err
		}
		return n, nil
	}

	len_data := len(data)
	send_len := 1024 - len(strconv.Itoa(len_data)+"~~")

	pre := strconv.Itoa(len_data) + "~~" + data[0:send_len]
	_, e := con.Write([]byte(pre))
	if e != nil {
		panic(e)
	}

	len_data = len_data - send_len

	for i := len_data; i > 0; {
		if len_data >= 1024 {
			preB := data[send_len : send_len+1024]
			n, e := con.Write([]byte(preB))
			if e != nil {
				return -1, e
			}
			send_len += n
			len_data -= n
			i -= n
		} else {
			preB := data[send_len : send_len+len_data]
			n, e := con.Write([]byte(preB))
			if e != nil {
				return -1, e
			}
			send_len += n
			len_data -= n
			i -= n
		}
	}
	return send_len, nil
}

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

	// conn.Write([]byte(encodedsOneChildJson))
	_, e := updatedsendData(encodedsOneChildJson, conn)
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

		// conn.Write([]byte(encodedsThreeMainJson))
		_, err_ := updatedsendData(encodedsThreeMainJson, conn)
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
				m.clientAesKey = sTwoChild.AESK
				m.hash = []byte(sFourChild.HS)
				m.clientName = sTwoChild.ID
				m.preHash = nil
				m.clientRsaPriKey = privateKey
				m.clientRsaPubKey = &publicKey

				m.con = conn
				m.isAllSetup = true
			} else {
				panic(errors.New("authentication failed. Something bad happen"))
			}
		}
	}
}

// Used to create a secured connection with Engine with the hellp of authenticateClient fucntion.
func connectoEngine(m *MAIN, address string, port string) {
	con, err := net.Dial("tcp", address+":"+port)
	if err != nil {
		fmt.Println(err)
		return
	}

	m.isAllSetup = false
	m.upgradedAuthenticator(con)
}

// Sends data to the client using the client name and channel
// Parameter:
//   	channel (string): channel on which you want this data is being listen or read.
// 		data (string)   : Data that you want to send.
// returns : n -> No. of bytes being send.
// 		 error -> If any...
func (m *MAIN) Send(channel string, data string) (int, error) {

	if len(data) >= 1 {

		var res Transport
		res.Type = "E-DSP"
		res.Channel = channel
		res.Name = m.clientName
		res.Data = data
		res.DateTime = time.Now().String()

		jsonres, err := json.Marshal(&res)
		handleError(err, "")
		cipherText, e_rr := aesEncryption(m.clientAesKey, jsonres)
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
		// n, err_ := m.con.Write([]byte(encodedCipherText))
		n, err_ := updatedsendData(encodedCipherText, m.con)
		handleError(err_, "")

		return n, err_

	} else {
		return -1, errors.New("message is too small to send")
	}
}

func updatedReadData(con net.Conn) ([]byte, error) {

	var _bufSize int = 1024
	var _bufData []byte = make([]byte, _bufSize)
	var size int
	var err error
	var nbytes int

	bufio.NewReader(con).ReadBytes('\n')
	nbytes, err = con.Write(_bufData)
	if err != nil {
		return nil, err
	}
	var dataList []string = strings.Split(string(_bufData), "~~")
	size, err = strconv.Atoi(dataList[0])
	r_size := size
	if err != nil {
		return nil, err
	}

	var store []byte
	size = size - len([]byte(dataList[1]))
	store = append(store, []byte(dataList[1])...)
	var nb int
	for i := size; i > 0; i = i - nb {
		if i >= 128 {
			nbytes, err = con.Write(_bufData)
			if err != nil {
				return nil, err
			}
			if nbytes == 0 {
				return nil, errors.New("0 bytes received")
			}
			nb = nbytes
			store = append(store, _bufData...)
		} else {
			var tempBuf []byte = make([]byte, i)
			nbytes, err = con.Write(_bufData)
			if nbytes == 0 {
				return nil, errors.New("0 bytes received")
			}
			if err != nil {
				return nil, err
			}
			nb = nbytes
			for _, i := range tempBuf {
				if i != 0 {
					store = append(store, i)
				}
			}
			return store, nil
		}
	}
	s := store[:r_size]

	return s, nil
}

// Used to initialise the server. It calls all the  internal functions
// and utilities needed for initilisation of server.
// Parameter:
// 		address (string): ipv4 address on which client wnat with connect Engine.
// 		port (string)   : port on which you want to connect with Engine.
// It returns a instance of *MAIN.
func (c *Client) Start(address string, port string) *MAIN {

	var setter Client
	setter.defaultSetter()
	var m MAIN
	m.client = &setter
	connectoEngine(&m, address, port)

	go m.handler()

	return &m
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
	m.client.hstruct._listenList[channel] = fn
}

// Reads data that is comming from Engine.
// This function works along with the Listen fucntion.
// This function is internally executed once throughout the client's life cycle.
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
					recvChildJson, e := aesDecryption(m.clientAesKey, recvChildCipherText)
					handleError(e, "")

					var recvChild Transport
					e_rr := json.Unmarshal(recvChildJson, &recvChild)
					handleError(e_rr, "")

					if recvChild.Type == "E-DSP" {
						if m.client.hstruct._listenList[recvChild.Channel] != nil {
							Caller := m.client.hstruct._listenList[recvChild.Channel]
							Caller(recvChild, m.Send, nil)
						}
					}

				}
			}
		}
	}
}
