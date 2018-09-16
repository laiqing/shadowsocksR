package main

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sun8911879/shadowsocksR"
	"github.com/sun8911879/shadowsocksR/tools/leakybuf"
	"github.com/sun8911879/shadowsocksR/tools/socks"
)

var dbgLog = log.New(os.Stdout, "[DEBUG] ", log.Ltime)

var (
	debug       = true
	readTimeout = 600 * time.Second
)

var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support 1 method now")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
)

// SSInfo fields that shadowsocks/shadowsocksr used only
type SSInfo struct {
	SSRInfo
	EncryptMethod   string
	EncryptPassword string
}

// SSRInfo fields that shadowsocksr used only
type SSRInfo struct {
	Obfs          string
	ObfsParam     string
	ObfsData      interface{}
	Protocol      string
	ProtocolParam string
	ProtocolData  interface{}
}

// BackendInfo all fields that a backend used
type BackendInfo struct {
	SSInfo
	Address string
	Type    string
}

func base64decode(str string) string {
	byteArray, _ := base64.RawURLEncoding.DecodeString(str)
	ret := string(byteArray)
	return ret
}

func main() {
	if len(os.Args) != 2 {
		log.Printf("ssrUrl not found\n")
	}
	ssrURL := base64decode(os.Args[1][6:])
	ssrURLArr := strings.Split(ssrURL, "/")
	paramArr := strings.Split(ssrURLArr[0], ":")
	if len(paramArr) != 6 {
		log.Printf("-- %s\n", ssrURLArr[0])
		log.Printf("url error, please")
		return
	}
	var (
		hostname      = paramArr[0]
		port          = paramArr[1]
		protocol      = paramArr[2]
		method        = paramArr[3]
		obfs          = paramArr[4]
		password      = paramArr[5]
		protocolParam = ""
		obfsParam     = ""
	)
	password = base64decode(password)
	queryMap, _ := url.ParseQuery(ssrURLArr[1])
	if val, ok := queryMap["protocolparam"]; ok {
		protocolParam = base64decode(val[0])
	}
	if val, ok := queryMap["obfsparam"]; ok {
		obfsParam = base64decode(val[0])
	}
	bi := &BackendInfo{
		Address: fmt.Sprintf("%s:%s", hostname, port),
		Type:    "ssr",
		SSInfo: SSInfo{
			EncryptMethod:   method,
			EncryptPassword: password,
			SSRInfo: SSRInfo{
				Protocol:      protocol,
				ProtocolParam: protocolParam,
				Obfs:          obfs,
				ObfsParam:     obfsParam,
			},
		},
	}
	if debug {
		dbgLog.Printf("hostname:%s port:%s protocol:%s method:%s obfs:%s password:%s protocolParam:%s obfsParam:%s\n", hostname, port, protocol, method, obfs, password, protocolParam, obfsParam)
	}
	bi.Listen()
}

func getRequest(conn net.Conn) (rawaddr []byte, host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip address start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int
	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}
	if buf[idCmd] != socksCmdConnect {
		err = errCmd
		return
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	rawaddr = buf[idType:reqLen]

	if debug {
		switch buf[idType] {
		case typeIPv4:
			host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
		case typeIPv6:
			host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
		case typeDm:
			host = string(buf[idDm0 : idDm0+buf[idDmLen]])
		}
		port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
		dbgLog.Printf("host:%s port:%d\n", host, port)
	}

	return
}

func (bi *BackendInfo) Listen() {
	listener, err := net.Listen("tcp", "0.0.0.0:6666")
	if err != nil {
		panic(err)
	}
	for {
		localConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go bi.Handle(localConn)
	}
}

func (bi *BackendInfo) handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)
	// version identification and method selection message in theory can have
	// at most 256 methods, plus version and nmethod field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved),
	// so it won't be such long in practice

	buf := make([]byte, 258)

	var n int
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	// make sure we get the nmethod field
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}
	if buf[idVer] != socksVer5 {
		return errVer
	}
	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2
	if n == msgLen { // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errAuthExtraData
	}
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{socksVer5, 0})
	return
}

func (bi *BackendInfo) Handle(src net.Conn) {
	// patch start
	closed := false

	var err error
	if err = bi.handShake(src); err != nil {
		log.Println("socks handshake:", err)
		return
	}
	rawaddr, addr, err := getRequest(src)
	if err != nil {
		log.Println("error getting request:", err)
		return
	}
	// Sending connection established message immediately to client.
	// This some round trip time for creating socks connection with the client.
	// But if connection failed, the client will get connection reset error.
	_, err = src.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		log.Println("send connection confirmation:", err)
		return
	}

	dst, err := bi.DialSSRConn(rawaddr)
	if err != nil {
		log.Println("Failed connect to shadowsocks server")
		return
	}
	defer func() {
		if !closed {
			src.Close()
		}
	}()

	go bi.Pipe(src, dst)
	bi.Pipe(dst, src)
	closed = true
	dbgLog.Println("closed connection to", addr)
}

func (bi *BackendInfo) DialSSRConn(rawaddr socks.Addr) (net.Conn, error) {
	u := &url.URL{
		Scheme: bi.Type,
		Host:   bi.Address,
	}
	v := u.Query()
	v.Set("encrypt-method", bi.EncryptMethod)
	v.Set("encrypt-key", bi.EncryptPassword)
	v.Set("obfs", bi.Obfs)
	v.Set("obfs-param", bi.ObfsParam)
	v.Set("protocol", bi.Protocol)
	v.Set("protocol-param", bi.ProtocolParam)
	u.RawQuery = v.Encode()

	ssrconn, err := shadowsocksr.NewSSRClient(u)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSR server failed :%v", err)
	}

	if bi.ObfsData == nil {
		bi.ObfsData = ssrconn.IObfs.GetData()
	}
	ssrconn.IObfs.SetData(bi.ObfsData)

	if bi.ProtocolData == nil {
		bi.ProtocolData = ssrconn.IProtocol.GetData()
	}
	ssrconn.IProtocol.SetData(bi.ProtocolData)

	if _, err := ssrconn.Write(rawaddr); err != nil {
		ssrconn.Close()
		return nil, err
	}
	return ssrconn, nil
}

// PipeThenClose copies data from src to dst, closes dst when done.
func (bi *BackendInfo) Pipe(src, dst net.Conn) error {
	defer dst.Close()
	buf := leakybuf.GlobalLeakyBuf.Get()
	defer leakybuf.GlobalLeakyBuf.Put(buf)
	for {
		src.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			dbgLog.Println(buf)
			if _, err := dst.Write(buf[0:n]); err != nil {
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			break
		}
	}
	return nil
}
