package stun

import (
	"io"
	"bytes"
	"errors"
	"strconv"
	"io/ioutil"
	"encoding/binary"
)

type (
	Response struct {
		Header 			Header
		Attributes 	[]Attrs
		Address 		string
		Port 				string
	}
	Header struct {
		Method 			int16
		Length 			int16
		MagicCookie int32
		Tid 				int32
	}
	Attrs struct {
		PacketType 	byte
		Data 	  		Body
	}
	Body struct {
		Family  	int
		Address 	string
		Port 			string
		Packet 		string
	}
)

// For more information - https://tools.ietf.org/html/rfc5389

// Processing received data
func Decode(buffer []byte) (Response, error) {
	if err := packetTest(buffer); err != nil { // Analysing package
		return Response{}, err
	}

	buf_header := buffer[:packet.HEADER_LENGTH]
	header, err := decodeHeader(buf_header) // processing header ...
	if err != nil {
		return Response{}, err
	}

	buf_attrs := buffer[packet.HEADER_LENGTH:]
	attrs, err  := decodeAttrs(buf_attrs, buf_header) // processing attributes ...
	if err != nil {
		return Response{}, err // error if anything will wrong
	} 

	response := Response{header, attrs, attrs[0].Data.Address, attrs[0].Data.Port}

	return response, nil
}

// Decoding header
func decodeHeader(buffer []byte) (Header, error) {
	header := Header{}
	buf := bytes.NewReader(buffer)

	var method int16
	binary.Read(buf, binary.BigEndian, &method)
	header.Method = method & packet.METHOD_MASK

	binary.Read(buf, binary.BigEndian, &header.Length)
	binary.Read(buf, binary.BigEndian, &header.MagicCookie)

	io.CopyN(ioutil.Discard, buf, 7)

	binary.Read(buf, binary.BigEndian, &header.Tid)

	return header, nil
}

// Decoding attributes
func decodeAttrs(buffer []byte, buffer_header []byte) ([]Attrs, error) {
	buf := bytes.NewReader(buffer)
	attributes := make([]Attrs, 0)
	offset := 0

	for offset < int(buf.Size()) {
		var body Body
		var packetType int16
		binary.Read(buf, binary.BigEndian, &packetType)
		offset += 2

		var length int16
		binary.Read(buf, binary.BigEndian, &length)
		offset += 2

		blockout := length % 4
		if (blockout > 0) {
			length += 4 - blockout
		}

		if (length == 0) || (int(length)+offset > int(buf.Size())) {
			break
		}

		value := buffer[offset:offset+int(length)]
		offset += int(length)

		io.CopyN(ioutil.Discard, buf, int64(offset))

		switch (int(packetType)) {
		case packet.ATTR["MAPPED_ADDRESS"]:
			body = mappedAddressDecoding(value);
		case packet.ATTR["XOR_MAPPED_ADDRESS"]:
			body = xorMappedAddressDecoding(value, buffer_header);
		case packet.ATTR["ERROR_CODE"]:
			error := errorCodeDecoding(value);
			return nil, error
		case packet.ATTR["UNKNOWN_ATTRIBUTES"]:
			unknownAttributesDecoding(value);
		}

		attributes = append(attributes, Attrs{byte(packetType), body})
	}

	return attributes, nil
}

// MAPPED-ADDRESS encoded (https://tools.ietf.org/html/rfc5389#section-15.1)
func mappedAddressDecoding(buffer []byte) Body {
	var body Body
	var decodedFamily int
	var stringAddress string
	
	family := binary.BigEndian.Uint16(buffer[:2])
	port := binary.BigEndian.Uint16(buffer[2:4])
	address := buffer[4:]

	if family == 0x02 {
		decodedFamily = 6
	} else {
		decodedFamily = 4
	}

	if decodedFamily == 4 {
		for i, part := range address {
			if i+1 != len(address) {
				stringAddress += strconv.Itoa(int(part)) + "."
			} else {
				stringAddress += strconv.Itoa(int(part))
			}
		}
	}

	body.Address = stringAddress
	body.Family = decodedFamily
	body.Port = strconv.Itoa(int(port))
	body.Packet = "MAPPED-ADDRESS"

	return body
}

// XOR-MAPPED-ADDRESS encoded (https://tools.ietf.org/html/rfc5389#section-15.2)
func xorMappedAddressDecoding(buffer []byte, buffer_header []byte) Body {
	buf := bytes.NewReader(buffer)

	var family 		  int16
	var decodedFamily int
	binary.Read(buf, binary.BigEndian, family)
	
	if family == 0x02 {
		decodedFamily = 6
	} else {
		decodedFamily = 4
	}

	magic := buffer_header[4:8]
	tid := buffer_header[8:20]

	var xport = buffer[2:4]
	var xaddress []byte
	var port 	 []byte
	var address  []byte
	var body 	 Body

	if decodedFamily == 4 {
		xaddress = buffer[4:8]
	} else {
		xaddress = buffer[4:20]
	}
	
	port = _xor(xport, magic[:2])

	if decodedFamily == 4 {
		address = _xor(xaddress, magic)
	} else {
		address = _xor(xaddress, append(magic, tid...))
	}

	var stringAddress string

	for i, part := range address {
		if i+1 != len(address) {
			stringAddress += strconv.Itoa(int(part)) + "."
		} else {
			stringAddress += strconv.Itoa(int(part))
		}
	}

	body.Family = decodedFamily
	body.Address = stringAddress
	body.Port = strconv.Itoa(int(binary.BigEndian.Uint16(port)))
	body.Packet = "XOR-MAPPED-ADDRESS"

	return body
}

// if error ...
func errorCodeDecoding(buffer []byte) error {
	block := binary.BigEndian.Uint32(buffer[:4])
	code := (block & 0x700) * 100 + block & 0xff
	reason := binary.BigEndian.Uint32(buffer[4:8])
	return errors.New("Error: code: "+string(code)+", reason: "+string(reason))
}

// if unknown attributes occur ...
func unknownAttributesDecoding(buffer []byte) []int {
	data := make([]int, 0)
	buf  := bytes.NewReader(buffer)
	for buf.Len() > 0 {
		var ukattr int16
		binary.Read(buf, binary.BigEndian, &ukattr)
		data = append(data, int(ukattr))
	}
	return data
}

// XOR simple decoder
func _xor(a []byte, b []byte) []byte {
	data := make([]byte, 0)

	if len(a) < len(b) {
		rem := a
		a = b
		b = rem
	}

	for i, _ := range a {
		data = append(data, a[i] ^ b[i])
	}

	return data
}

// Testing of package
func packetTest(buffer []byte) error {
	var block int
	buf := bytes.NewReader(buffer)
	_ = binary.Read(buf, binary.LittleEndian, &block)
	if ((block & 0x80 == 0) && (block & 0x40 == 0)) {
		return nil
	}
	return errors.New("This packet is not a stun packet")
}