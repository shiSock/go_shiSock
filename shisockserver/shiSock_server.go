package shisockserver

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	EPOLLET        = 1 << 31
	MaxEpollEvents = 32
)

var (
	MaxCC = 10000 // max concurrent connections
)

func (s *Server) Init() {
	s.defaultSetter()
	if IsIPv4(s.Address) {
		s.isAip4 = true
		s.isAip6 = false
	} else {
		s.isAip6 = true
		s.isAip6 = false
	}
}

func (s *Server) defaultSetter() {

	if s.Address == "" {
		s.Address = "127.0.0.1"
	}
	if s.Port == 0 {
		s.Port = 8080
	}

	if s.stimeout == 0 {
		s.stimeout = 1
	}
	if s.MaxConnection == 0 || s.MaxConnection < 100000 {
		s.MaxConnection = 100000
	}
	if len(s.Channels) == 0 {
		s.Channels = []string{}
		s.Channels = append(s.Channels, "main")
	}
	var Handler handlerData
	Handler._listenList = make(map[string]func(EngineTransport, func(string, string, string) (int, error), []string))
	Handler._listenChannel = make(chan []byte)
	s.hstruct = &Handler
}

func handleError(err error) {
	_, _, line, _ := runtime.Caller(1)
	if err != nil {
		log.Fatal("Line: ", line, " --> ", err)
	}
}

func shuffleID(id string) string {
	rand.Seed(time.Now().Unix())

	inRune := []rune(id)
	rand.Shuffle(len(inRune), func(i, j int) {
		inRune[i], inRune[j] = inRune[j], inRune[i]
	})
	return string(inRune)
}

func UEH(err error, msg string, doPanic bool, exitFunc bool, clientFD int) bool {
	if err != nil {
		var strCFD string = strconv.Itoa(clientFD)
		var stackSlice []byte = make([]byte, 512)
		n := runtime.Stack(stackSlice, false)

		AddLog("===================== | [ERROR] [" + time.Now().String() + "] | ======================")
		AddLog(msg + ",FD -> " + strCFD + " : " + err.Error())
		AddLog("TRACE :")
		AddLog(string(stackSlice[0:n]))

		if doPanic {
			AddLog("=======================================================================================================")
			AddLog("")
			panic(err)
		}
		if exitFunc {
			var err error = syscall.Close(clientFD)
			var errString string
			if err != nil {
				errString = err.Error()
			} else {
				errString = "ok"
			}
			AddLog("closing Connection with client: " + strconv.Itoa(clientFD) + " => " + errString)
			AddLog("=======================================================================================================")
			AddLog("")
			return true
		} else {
			AddLog("=======================================================================================================")
			AddLog("")
			return false
		}
	} else {
		return false
	}
}

func (s *Server) remove(clientFD int) error {
	err := unix.EpollCtl(s.epollFD, syscall.EPOLL_CTL_DEL, clientFD, nil)
	if err != nil {
		return err
	}
	s.lock.Lock()
	name := s.connections[clientFD].name
	delete(s.connections, clientFD)
	delete(s.fdStore, name)
	s.lock.Unlock()
	return nil
}

func ReceiveLog(data string) error {
	f, err := os.OpenFile("./logfile/shiSock-receiver-log.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	if _, err = f.WriteString(data + "\n"); err != nil {
		panic(err)
	}
	return nil
}

func updatedReadData(clientFD int) ([]byte, int, error) {

	var _bufSize int = 1024
	var _bufData []byte = make([]byte, _bufSize)
	var size int
	var err error
	var nbytes int

	nbytes, err = syscall.Read(clientFD, _bufData)
	if err != nil {
		return nil, -1, err
	}
	if nbytes < 1024 {
		return _bufData, nbytes, nil
	}
	var dataList []string = strings.Split(string(_bufData), "~~")
	size, err = strconv.Atoi(dataList[0])
	r_size := size
	if err != nil {
		return nil, -1, err
	}

	var store []byte
	size = size - len([]byte(dataList[1]))
	store = append(store, []byte(dataList[1])...)
	var nb int
	for i := size; i > 0; i = i - nb {
		if i >= 128 {
			nbytes, err = syscall.Read(clientFD, _bufData)
			if err != nil {
				return nil, -1, err
			}
			if nbytes == 0 {
				return nil, -1, errors.New("0 bytes received")
			}
			nb = nbytes
			store = append(store, _bufData...)
		} else {
			var tempBuf []byte = make([]byte, i)
			nbytes, err = syscall.Read(clientFD, tempBuf)
			if nbytes == 0 {
				return nil, -1, errors.New("0 bytes received")
			}
			if err != nil {
				return nil, -1, err
			}
			nb = nbytes
			for _, i := range tempBuf {
				if i != 0 {
					store = append(store, i)
				}
			}
		}
	}
	s := store[:r_size]

	return s, len(s), nil
}

func (s *Server) upgradedAuthenticator(serverFD int, clientFD int, epFD int) {
	Bytes, _, err := updatedReadData(clientFD)
	if UEH(err, "Error While First Read of authenticateClient", false, true, clientFD) {
		return
	}

	var mainJsonString []byte = Decode(string(Bytes))
	var sOneMain parent
	e := json.Unmarshal(mainJsonString, &sOneMain)
	if UEH(e, "Error while Unmarshaling the json data", false, true, clientFD) {
		return
	}

	if sOneMain.TP == "auth-step-1" {
		if sOneMain.MD == "~~" {

			var decodedsOneChild []byte = Decode(sOneMain.CJ)
			var sOneChild authStep1
			var sE error = json.Unmarshal(decodedsOneChild, &sOneChild)
			if UEH(sE, "Error while Unmarshaling the json data", false, true, clientFD) {
				return
			}

			decodedRsaPubKey := Decode(sOneChild.SPUBK)
			publicKey, err := LoadKey(decodedRsaPubKey)
			if UEH(err, "Error while loading the public key", false, true, clientFD) {
				return
			}

			if VarifySignature(publicKey, sOneChild.HS, sOneChild.SN) {

				var identifier string = Encode(GenerateAesKey(14))
				identifier = Encode([]byte(shuffleID(identifier)))

				var aesKey []byte = GenerateAesKey(32)
				var conMsg []byte = GenerateAesKey(20)

				var sTwoChild authStep2
				sTwoChild.AESK = aesKey
				sTwoChild.CM = conMsg
				sTwoChild.ID = identifier

				sTwoChildJson, err := json.Marshal(sTwoChild)
				if UEH(err, "Error while Marshalling struct to json", false, true, clientFD) {
					return
				}

				ciphertext, err := RsaEncrypt(*publicKey, sTwoChildJson)
				if UEH(err, "Error while Encrypting sTwoChildJson data in step 2", false, true, clientFD) {
					return
				}

				var encodedCipherText string = Encode(ciphertext)

				var sTwoMain parent
				sTwoMain.TP = "auth-step-2"
				sTwoMain.MD = "~~"
				sTwoMain.CJ = encodedCipherText

				sTwoMainJson, err := json.Marshal(sTwoMain)
				if UEH(err, "Error while marshalling struct to json", false, true, clientFD) {
					return
				}

				var encodedsTwoMainJson string = Encode(sTwoMainJson)

				_, er := syscall.Write(clientFD, []byte(encodedsTwoMainJson+"\n"))
				if UEH(er, "Error while writing data to the client", false, true, clientFD) {
					return
				}

				// Read the signed msg
				Buf, _, e_rr := updatedReadData(clientFD)
				if UEH(e_rr, "Error while reading the data in Step three", false, true, clientFD) {
					return
				}

				var decodedsMainThreeJson []byte = Decode(string(Buf))

				var sThreeMain parent
				err__ := json.Unmarshal(decodedsMainThreeJson, &sThreeMain)
				if UEH(err__, "Error while unmarshalling the data", false, true, clientFD) {
					return
				}

				if sThreeMain.TP == "auth-step-3" {
					if sThreeMain.MD == "~~" {

						var decodedsThreeChild []byte = Decode(sThreeMain.CJ)
						sThreeplainText, err := AesDecryption(aesKey, decodedsThreeChild)
						if UEH(err, "Error while decrypting data in Step 3", false, true, clientFD) {
							return
						}
						var sThreeChild authStep3

						e__r := json.Unmarshal(sThreeplainText, &sThreeChild)
						if UEH(e__r, "Error while unmarshalling the data in step 3", false, true, clientFD) {
							return
						}

						if VarifySignature(publicKey, sThreeChild.HS, sThreeChild.SN) {

							h := sha256.New()
							h.Write(sThreeChild.CM)
							encodedStr := Encode(h.Sum(nil))

							var sFourChild authStep4
							sFourChild.HS = encodedStr

							sFourChildjson, err_ := json.Marshal(sFourChild)
							if UEH(err_, "Error while marshaling sFourChild struct in Step 4", false, true, clientFD) {
								return
							}

							// aes encryption
							sFCJCipherText, err_r := AesEncryption(aesKey, sFourChildjson)
							if UEH(err_r, "Error while encrypting sFourChildjson data in step 4 of authentication of client", false, true, clientFD) {
								return
							}

							var encodedsFCJCipherText string = Encode(sFCJCipherText)
							var sFourMain parent
							sFourMain.TP = "auth-step-4"
							sFourMain.MD = "~~"
							sFourMain.CJ = encodedsFCJCipherText

							sFourMainjson, err__r := json.Marshal(sFourMain)
							if UEH(err__r, "Error while marshaling sFourMainJson data in step 4", false, true, clientFD) {
								return
							}

							var encodedsFMJ string = Encode(sFourMainjson)

							syscall.Write(clientFD, []byte(encodedsFMJ+"\n"))

							// Key Sharing process completed....

							// Detail registry process starts...

							var e_rrr error = syscall.SetNonblock(clientFD, true)
							if UEH(e_rrr, "Error while setting client connection as non-blocking", false, true, clientFD) {
								return
							}

							var event syscall.EpollEvent

							event.Events = syscall.EPOLLIN | EPOLLET
							event.Fd = int32(clientFD)

							time.Sleep(1 * time.Second)

							if err := syscall.EpollCtl(epFD, syscall.EPOLL_CTL_ADD, clientFD, &event); err != nil {
								AddLog("epoll_ctl: " + err.Error())
								os.Exit(1)
							}

							var detail Detail
							detail.aesKey = aesKey
							detail.fd = clientFD
							detail.name = identifier
							detail.rsaKey = decodedRsaPubKey
							detail.Hstatus = true
							detail.isInInputs = false
							detail.isInOutputs = true

							s.lock.Lock()
							var count int = s.maxClientConnected
							s.maxClientConnected = count + 1
							s.connections[clientFD] = &detail
							s.fdStore[detail.name] = clientFD
							s.lock.Unlock()

						} else {
							AddLog("Second Signature Varification Failed...")
							return
						}

					} else {
						AddLog("Error in step-3 ~~")
					}
				} else {
					AddLog("Error in step 3 auth-step-3")
				}

			} else {
				AddLog("First Signature Varification Failed...")
				return
			}

		}
	}
}

func (s *Server) receive(events [32]syscall.EpollEvent, ev int, con net.Conn) {
	clientFD := int(events[ev].Fd)

	s.lock.Lock()
	detail := s.connections[clientFD]
	detail.isIdle = false
	s.lock.Unlock()

	ReceiveLog("listening on Fd: " + strconv.Itoa(clientFD))
	Bytes, nbytes, er := updatedReadData(clientFD)

	if er != nil && nbytes == -1 {
		ReceiveLog("FD: " + strconv.Itoa(clientFD) + " gives zero on read  | removing...")
		e := s.remove(clientFD)
		handleError(e)
		ReceiveLog("Fd: " + strconv.Itoa(clientFD) + " Client Removed From The Epoll Event Loop")
		return
	}

	if er == nil {
		if nbytes == 0 {
			ReceiveLog("FD: " + strconv.Itoa(clientFD) + " gives zero on read  | removing...")
			e := s.remove(clientFD)
			handleError(e)
			ReceiveLog("Fd: " + strconv.Itoa(clientFD) + " Client Removed From The Epoll Event Loop")
		} else {
			ReceiveLog("nbytes: " + strconv.Itoa(nbytes))

			strList := strings.Split(string(Bytes), "~|||~")
			strList = strList[0 : len(strList)-1]

			for _, msg := range strList {

				msgList := strings.Split(msg, ".")
				msgLen, e := strconv.Atoi(msgList[1])
				if e != nil {
					panic(e)
				}
				actualMsg := msgList[0]

				if msgLen == len(actualMsg) {

					var decodedSendMainJson []byte = Decode(actualMsg)
					var sendMain parent

					err_ := json.Unmarshal(decodedSendMainJson, &sendMain)
					if UEH(err_, "Error while unmarshalling the data during receiving message from client", false, false, 0) {
						return
					}

					if sendMain.TP == "auth-E-DSP" && sendMain.MD == "~~" {
						decodedCipherText := Decode(sendMain.CJ)

						plainText, err := AesDecryption(detail.aesKey, decodedCipherText)
						handleError(err)

						var trans EngineTransport
						er_r := json.Unmarshal(plainText, &trans)
						handleError(er_r)

						if trans.Type == "E-DSP" {
							channel := trans.Channel
							fn := s.hstruct._listenList[channel]
							fn(trans, s.Send, nil)
							return

						} else if trans.Type == "3e45rt5rf5" && trans.Channel == "INTERNAL" {
							{
							}
						}
					}
				}
			}

			if detail.close {
				syscall.Close(clientFD)
				e := s.remove(clientFD)
				handleError(e)
			}
			detail.isIdle = true
		}
	}
}

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

type Func func(EngineTransport, func(string, string, string) (int, error), []string)

func (s *Server) Listen(channel string, fn Func, args []string) {
	s.hstruct._listenList[channel] = fn
}

func (s *Server) Send(name string, channel string, data string) (int, error) {
	var fd int = s.fdStore[name]
	d := *s.connections[fd]
	res, err := _prepareData(name, channel, data, d)
	if err != nil {
		return 0, err
	}
	i, e := _send(fd, res)
	return i, e
}

func (s *Server) Close(name string) {
	fd := s.fdStore[name]
	s.remove(fd)
}

func (s *Server) Isclosed(name string) bool {
	fd := s.fdStore[name]
	if fd == 0 {
		return true
	} else {
		return false
	}
}

func (s *Server) Start() {

	AddLog("")
	AddLog("=========================[ WELCOME TO shiSock ENGINE ]=========================")
	AddLog("")
	AddLog("DateTime       : " + time.Now().String())
	AddLog("Process PID    : " + strconv.Itoa(os.Getpid()))

	AddLog("Server Address : " + s.Address)
	AddLog("Server Port    : " + strconv.Itoa(s.Port))
	AddLog("")

	// Increase resources limitations
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		panic(err)
	}
	if rLimit.Max < uint64(s.MaxConnection) {
		rLimit.Cur = uint64(s.MaxConnection)
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
			fmt.Println("Error while increasing the resources limitations: ", err)
		}
	}

	s.connections = make(map[int]*Detail)
	s.lock = &sync.RWMutex{}
	s.fdStore = make(map[string]int)

	var event syscall.EpollEvent
	var events [MaxEpollEvents]syscall.EpollEvent

	fd, err := syscall.Socket(syscall.AF_INET, syscall.O_NONBLOCK|syscall.SOCK_STREAM, 0)
	if err != nil {
		AddLog("Error while creating parent socket: " + err.Error())
		os.Exit(1)
	}
	defer syscall.Close(fd)

	if err := syscall.SetNonblock(fd, true); err != nil {
		AddLog("Error while setting fd as Non-Blocking: " + err.Error())
		os.Exit(1)
	}

	if s.isAip4 {
		fmt.Println("starting ipv4 server")
		addr := syscall.SockaddrInet4{Port: s.Port}
		copy(addr.Addr[:], net.ParseIP(s.Address).To4())

		syscall.Bind(fd, &addr)
		syscall.Listen(fd, s.MaxConnection)
	} else if s.isAip6 {
		fmt.Println("starting ipv6 server")
		addr := syscall.SockaddrInet6{Port: s.Port}
		copy(addr.Addr[:], net.ParseIP(s.Address).To16())

		syscall.Bind(fd, &addr)
		syscall.Listen(fd, s.MaxConnection)
	}

	epfd, e := syscall.EpollCreate1(0)
	if e != nil {
		AddLog("Error while EpollCreate1 : " + e.Error())
		os.Exit(1)
	}
	defer syscall.Close(epfd)

	event.Events = syscall.EPOLLIN
	event.Fd = int32(fd)

	s.serverFD = fd
	s.epollFD = epfd

	if e = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &event); e != nil {
		AddLog("Error while epoll_ctl: " + e.Error())
		os.Exit(1)
	}

	for {
		time.Sleep(1 * time.Second)

		nevents, e := syscall.EpollWait(epfd, events[:], 1)
		if e != nil {
			if e.Error() == "interrupted system call" {
				AddLog("Avoiding Interrupted System Call on syscall.EpollWait...")
				continue
			} else {
				AddLog("epoll_wait: " + e.Error())
			}
		}

		for ev := 0; ev < nevents; ev++ {

			// checking that the fd is the parent fd
			if int(events[ev].Fd) == fd {
				connFd, _, err := syscall.Accept(fd)
				if err != nil {
					AddLog("Error while accepting new connection : " + err.Error())
					continue
				}

				go s.upgradedAuthenticator(fd, connFd, epfd)

			} else {
				go s.receive(events, ev, s.con)
			}
		}

	}
}

func _prepareData(name string, channel string, data string, detail Detail) (string, error) {
	var res EngineTransport
	res.Channel = channel
	res.Data = data
	res.DateTime = time.Now().String()
	res.Name = name
	res.Type = "E-DSP"

	plainText, err_ := json.Marshal(res)
	handleError(err_)

	cipherText, err := AesEncryption(detail.aesKey, plainText)
	handleError(err)

	encodedCipherText := Encode(cipherText)

	var sendMainServer parent
	sendMainServer.TP = "auth-E-DSP"
	sendMainServer.MD = "~~"
	sendMainServer.CJ = encodedCipherText

	sendMainServerJson, e := json.Marshal(sendMainServer)
	if e != nil {
		return "", e
	}

	var EncodedSMSJ string = Encode(sendMainServerJson)
	return EncodedSMSJ, nil
}

func _send(fd int, data string) (int, error) {
	n, err := syscall.Write(fd, []byte(data+"\n"))
	if UEH(err, "Error while marshling data during by-pass of data from engine to server", false, false, 0) {
		return 0, err
	}
	return n, nil
}
