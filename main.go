package main
import (
	"log"
	"net"
	"fmt"
	"os"
	"encoding/binary"
	"errors"
	"io"
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	service := ":8443"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)
	f := make(chan forward)
	go start(f)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go createForwardChan(conn,f)
	}
}

func start(forwardChan chan forward){
	for {
		select {
			case f := <-forwardChan:
				go handle(f)
		}
	}
}

func handle(f forward){
	//defer f.Server.Close()
	//defer f.Client.Close()
	_,err := f.Server.Write(f.Data)
	if err != nil {
		log.Println("首次发送数据失败",err)
	}
	//log.Println(n)
	go io.Copy(f.Server, f.Client)
	go io.Copy(f.Client, f.Server)
}

func createForwardChan(conn net.Conn,forwardChan chan forward)(){
	buff := make([]byte,4096)
	n,err := conn.Read(buff)
	if err != nil {
		log.Println(err)
		return
	}
	serverName := getServerName(buff[0:n])
	if serverName == "" {
		log.Println("获取主机名失败")
		return
	}
	server,err := connectTo(serverName)
	if err != nil {
		log.Println("连接远程服务器失败",serverName,err)
		return
	}
	f := forward{}
	f.Client = conn
	f.Server = server
	f.Data = buff[0:n]
	forwardChan <- f
}

func connectTo(hostname string) (net.Conn,error) {
	ns, err := net.LookupHost(hostname)
	var addr string
	if err != nil {
		return nil,err
	}
	if len(ns) > 0 {
		addr = ns[0]
	}else{
		return nil,errors.New("Unknown host")
	}
	service := addr+":443"
	//service = "14.215.177.38:443"
	//log.Println(addr)
	//service := addr+":443"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	if err !=nil {
		return nil,err
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err !=nil {
		return nil,err
	}
	return conn,nil
}

type forward struct {
	Client net.Conn
	Server net.Conn
	Data   []byte
}

func getServerName(data []byte) string {
	//client hello 数据解析
	// content type(1)|version (2)|length (2) |handshake type (1) |length (3) | version 2 |random(32)
	// session id length(1) |cipher length (2) |cipher data (cipher length) | compression length (1)
	//compress methods (1) | extensions length (2)

	// extenstions truct :
	//type(2) |  length (2) | list_struct (length)

	//list_struct:
	//length (2) | type (1) | length (2) |data (length)

	serverName := ""
	//log.Println(len(data))
	if data[5] != 1 {
		log.Println("not client hello")
		return ""
	}
	if len(data) < 47 {
		log.Println("data er")
		return ""
	}
	sessionIdLen := int(data[43])
	cipherDataStart := int(44 + sessionIdLen)
	data = data[cipherDataStart:]
	var cipherLenByte []byte = []byte{0, 0, data[0], data[1]}
	//log.Print(cipherLenByte)
	cipherLen := binary.BigEndian.Uint32(cipherLenByte)
	//log.Println(sessionIdLen)
	//compression length
	check := int(2 + cipherLen + 1)
	if len(data) < check {
		log.Println("data er")
		return ""
	}
	data = data[2+cipherLen:]
	compressionLength := int(data[0])
	check = int(compressionLength + 2)
	if len(data) < check {
		log.Println("data er")
		return ""
	}
	//extensions length
	check = int(compressionLength + 2)
	if len(data) < check {
		log.Println("data er")
		return ""
	}
	data = data[1+compressionLength:]
	var extensionsLenByte []byte = []byte{0, 0, data[0], data[1]}
	extensionLen := binary.BigEndian.Uint32(extensionsLenByte)
	//log.Println(extensionLen)
	check = 3
	if len(data) < check {
		log.Println("data er")
		return ""
	}
	check = int(extensionLen)
	if len(data) < check {
		log.Println("data er")
		return ""
	}
	data = data[2:]
	for {
		check = 4
		if len(data) < check {
			log.Println("data er")
			return ""
		}
		extensionTypeByte := []byte{0, 0, data[0], data[1]}
		extensionType := binary.BigEndian.Uint32(extensionTypeByte)
		//log.Println(extensionType)
		extensionLenByte := []byte{0, 0, data[2], data[3]}
		extensionLen := binary.BigEndian.Uint32(extensionLenByte)
		check = int(4 + extensionLen + 1)
		if len(data) < check {
			log.Println("data er")
			return ""
		}
		if extensionType != 0 {
			data = data[4+extensionLen:]
		} else {
			//serverName = string(data[4:extensionTypeLen])
			data = data[4:extensionLen+4]
			//看包里面servername 是一个list ，只读取第一个
			//list leng 2个字节,serverName元素序号 一个字节,第一个元素长度 2个字节，所以获取第一个元素的长度是 data[3:5]
			check = 4
			if len(data) < check {
				log.Println("data er")
				return ""
			}
			serverName0Byte := []byte{0, 0, data[3], data[4]}
			serverName0Len := binary.BigEndian.Uint32(serverName0Byte)
			//log.Println(serverName0Len)
			check = int(5 + serverName0Len)
			if len(data) < check {
				log.Println("data er")
				return ""
			}
			serverName = string(data[5:serverName0Len+5])
			return serverName
		}
	}
	return serverName
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
