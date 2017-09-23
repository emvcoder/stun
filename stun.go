package stun

import (
	"net"
	"math"
	"time"
	"bytes"
	"math/rand"
	"encoding/binary"
)

type (
	Package struct {
		ATTR 							map[string]int
		BINDING_CLASS 		int
		ERROR_CODE 				map[int]string
		MAGIC_COOKIE 			int
		MAX_TRANSACTIONID int
		METHOD_MASK 			int16
		METHOD 						map[string]int
		HEADER_LENGTH 		int
		MESSAGE 					[]byte
	}
)

var (
	Address, Port string
	METHOD = map[string]int{
		"REQUEST": 		0x0000,
		"INDICATION": 0x0010,
		"RESPONSE_S": 0x0100,
		"RESPONSE_E": 0x0110,
	}
	ERROR_CODE = map[int]string{
		300: "Try Alternate",
		400: "Bad Request",
		401: "Unauthorized",
		420: "Unknown Attribute",
		438: "Stale Nonce",
		500: "Server Error",
	};
	ATTR = map[string]int{
		"MAPPED_ADDRESS":     0x0001,
		"USERNAME":           0x0006,
		"MESSAGE_INTEGRITY":  0x0008,
		"ERROR_CODE":         0x0009,
		"UNKNOWN_ATTRIBUTES": 0x000A,
		"REALM":              0x0014,
		"NONCE":              0x0015,
		"XOR_MAPPED_ADDRESS": 0x0020,
		"SOFTWARE":           0x8022,
		"ALTERNATE_SERVER":   0x8023,
		"FINGERPRINT":        0x8028,
	};
	packet = Package{ATTR, 0x0001, ERROR_CODE, 0x2112A442, int(math.Pow(2, float64(32))), 0x0110, METHOD, 20, nil}
)

// Preparing packet for the request
func (p *Package) preparePacket() {
	transaction := packet.getTransactionId()
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, int16(packet.BINDING_CLASS & 0x3fff))
	binary.Write(buffer, binary.BigEndian, int16(0))
	binary.Write(buffer, binary.BigEndian, int32(packet.MAGIC_COOKIE))
	binary.Write(buffer, binary.BigEndian, int32(0))
	binary.Write(buffer, binary.BigEndian, int32(0))
	binary.Write(buffer, binary.BigEndian, int32(transaction))
	p.MESSAGE = buffer.Bytes()
}

// Connecting with stun server
func getConnection(service string) net.Conn {
	address, _ := net.ResolveUDPAddr("udp", service)
	conn, err := net.DialUDP("udp", nil, address)
	if err != nil {
		panic(err)
	}
	return conn
}

// Installing settings
func Set(address string, port string) {
	Address = address
	Port = port
}

// Getting and decoding data from the stun server
func Get() (Response, error) {
	rand.Seed(time.Now().UnixNano())

	conn := getConnection(Address+":"+Port)	// connecting
	defer conn.Close()
	
	packet.preparePacket() // prepatring packet

	conn.Write(packet.MESSAGE)
	reply := make([]byte, 256)
	_, err := conn.Read(reply)
	if err != nil {
		return Response{}, err
	}

	resp, err := Decode(reply) // decoding received data
	if err != nil {
		return Response{}, err
	}

	return resp, nil
}

// Getting random transaction identifier
func (p *Package) getTransactionId() int {
	bytes := rand.Intn(p.MAX_TRANSACTIONID)
	return bytes
}