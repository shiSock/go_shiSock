package shisockserver

import (
	"net"
	"sync"
)

type handlerData struct {
	_listenChannel chan []byte
	_listenList    map[string]func(EngineTransport, func(string, string, string) (int, error), []string)
}

type Detail struct {
	fd          int
	name        string
	Hstatus     bool
	rsaKey      []byte
	aesKey      []byte
	isInInputs  bool
	isInOutputs bool
	isIdle      bool
	close       bool
}

type Server struct {
	Address            string
	Port               int
	isAip4             bool
	isAip6             bool
	stimeout           int
	MaxConnection      int
	Channels           []string
	hstruct            *handlerData
	serverFD           int
	epollFD            int
	connections        map[int]*Detail
	fdStore            map[string]int
	lock               *sync.RWMutex
	con                net.Conn
	maxClientConnected int
}

type EngineTransport struct {
	Name     string `json:"nm"`
	DateTime string `json:"dttm"`
	Data     string `json:"dt"`
	Channel  string `json:"chnl"`
	Type     string `json:"tp"`
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
