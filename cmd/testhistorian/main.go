package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"math/big"
	math_rand "math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/awcullen/historian/timescaledb"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

/*
docker run -d --name timescaledb -p 5432:5432 -e POSTGRES_PASSWORD=password timescale/timescaledb:latest-pg14
*/

const (
	simulationPeriod       = 500 // ms
	historianConnectionURI = "postgres://postgres:password@127.0.0.1:5432"
)

var (
	host, _         = os.Hostname()
	port            = 46010
	SoftwareVersion = "0.3.0"
)

func main() {

	// create directory with certificate and key, if not found.
	if err := ensurePKI(); err != nil {
		log.Println("Error creating PKI.")
		return
	}

	// userids for testing
	userids := []ua.UserNameIdentity{
		{UserName: "root", Password: "secret"},
		{UserName: "user1", Password: "password"},
		{UserName: "user2", Password: "password1"},
	}
	for i := range userids {
		hash, _ := bcrypt.GenerateFromPassword([]byte(userids[i].Password), 8)
		userids[i].Password = string(hash)
	}

	// create the endpoint url from hostname and port
	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", host, port)

	// open connection to historian
	historian, err := timescaledb.Open(context.Background(), historianConnectionURI, "test")
	if err != nil {
		log.Println("Error connecting to historian.")
	}

	// create server
	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI: fmt.Sprintf("urn:%s:testserver", host),
			ProductURI:     "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{
				Text:   fmt.Sprintf("testserver@%s", host),
				Locale: "en",
			},
			ApplicationType:     ua.ApplicationTypeServer,
			GatewayServerURI:    "",
			DiscoveryProfileURI: "",
			DiscoveryURLs:       []string{endpointURL},
		},
		"./pki/server.crt",
		"./pki/server.key",
		endpointURL,
		server.WithBuildInfo(
			ua.BuildInfo{
				ProductURI:       "http://github.com/awcullen/opcua",
				ManufacturerName: "awcullen",
				ProductName:      "testserver",
				SoftwareVersion:  SoftwareVersion,
			}),
		server.WithAnonymousIdentity(true),
		server.WithAuthenticateUserNameIdentityFunc(func(userIdentity ua.UserNameIdentity, applicationURI string, endpointURL string) error {
			valid := false
			for _, user := range userids {
				if user.UserName == userIdentity.UserName {
					if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userIdentity.Password)); err == nil {
						valid = true
						break
					}
				}
			}
			if !valid {
				return ua.BadUserAccessDenied
			}
			// log.Printf("Login user: %s from %s\n", userIdentity.UserName, applicationURI)
			return nil
		}),
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
		server.WithServerDiagnostics(true),
		server.WithHistorian(historian),
		// server.WithTrace(),
	)
	if err != nil {
		os.Exit(1)
	}

	// add namespace, save index for later
	nm := srv.NamespaceManager()
	nsi := nm.Add("http://github.com/awcullen/opcua/testserver/")

	// add 'Component' object.
	component := server.NewObjectNode(
		ua.NodeIDNumeric{NamespaceIndex: nsi, ID: 1},
		ua.QualifiedName{NamespaceIndex: nsi, Name: "Component"},
		ua.LocalizedText{Text: "Component"},
		ua.LocalizedText{Text: "A component object for testing."},
		nil,
		[]ua.Reference{ // add object to 'Objects' folder
			{
				ReferenceTypeID: ua.ReferenceTypeIDOrganizes,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.ObjectIDObjectsFolder},
			},
		},
		0,
	)
	// add 'Boolean' property
	propBool := server.NewVariableNode(
		ua.NodeIDNumeric{NamespaceIndex: nsi, ID: 2},
		ua.QualifiedName{NamespaceIndex: nsi, Name: "Boolean"},
		ua.LocalizedText{Text: "Boolean"},
		ua.LocalizedText{Text: "A Boolean variable for testing."},
		nil,
		[]ua.Reference{ // add property to 'Component' object
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasProperty,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: component.NodeID()},
			},
		},
		ua.DataValue{},
		ua.DataTypeIDBoolean,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead|ua.AccessLevelsHistoryRead,
		250.0,
		true,
		historian,
	)
	// add 'Int64' property
	propInt64 := server.NewVariableNode(
		ua.NodeIDNumeric{NamespaceIndex: nsi, ID: 3},
		ua.QualifiedName{NamespaceIndex: nsi, Name: "Int64"},
		ua.LocalizedText{Text: "Int64"},
		ua.LocalizedText{Text: "An Int64 variable for testing."},
		nil,
		[]ua.Reference{ // add property to 'Component' object
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasProperty,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: component.NodeID()},
			},
		},
		ua.DataValue{},
		ua.DataTypeIDInt64,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead|ua.AccessLevelsHistoryRead,
		250.0,
		true,
		historian,
	)
	// add 'Double' property
	propDouble := server.NewVariableNode(
		ua.NodeIDNumeric{NamespaceIndex: nsi, ID: 4},
		ua.QualifiedName{NamespaceIndex: nsi, Name: "Double"},
		ua.LocalizedText{Text: "Double"},
		ua.LocalizedText{Text: "A Double variable for testing."},
		nil,
		[]ua.Reference{ // add property to 'Component' object
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasProperty,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: component.NodeID()},
			},
		},
		ua.DataValue{},
		ua.DataTypeIDDouble,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead|ua.AccessLevelsHistoryRead,
		250.0,
		true,
		historian,
	)
	// add 'String' property
	propString := server.NewVariableNode(
		ua.NodeIDNumeric{NamespaceIndex: nsi, ID: 5},
		ua.QualifiedName{NamespaceIndex: nsi, Name: "Double"},
		ua.LocalizedText{Text: "String"},
		ua.LocalizedText{Text: "A String variable for testing."},
		nil,
		[]ua.Reference{ // add property to 'Component' object
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasProperty,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: component.NodeID()},
			},
		},
		ua.DataValue{},
		ua.DataTypeIDString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead|ua.AccessLevelsHistoryRead,
		250.0,
		true,
		historian,
	)
	// add new nodes to namespace
	nm.AddNodes([]server.Node{
		component,
		propBool,
		propInt64,
		propDouble,
		propString,
	})

	// Simulate process variables changing every second. Server stores values in historian.
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t := time.Now().UTC() 
				propBool.SetValue(ua.NewDataValue(bool(t.Second()%2 != 0), 0, t, 0, t, 0))
				propInt64.SetValue(ua.NewDataValue(int64(math_rand.Intn(math.MaxInt64)), 0, t, 0, t, 0))
				propDouble.SetValue(ua.NewDataValue(math_rand.Float64(), 0, t, 0, t, 0))
				propString.SetValue(ua.NewDataValue(t.Format(time.StampMilli), 0, t, 0, t, 0))
			case <-srv.Closing():
				return
			}
		}
	}()

	go func() {
		// wait for signal (this conflicts with debugger currently)
		log.Println("Press Ctrl-C to exit...")
		waitForSignal()

		log.Println("Stopping server...")
		srv.Close()
	}()

	// start server
	log.Printf("Starting server '%s' at '%s'\n", srv.LocalDescription().ApplicationName.Text, srv.EndpointURL())
	if err := srv.ListenAndServe(); err != ua.BadServerHalted {
		log.Println(errors.Wrap(err, "Error starting server"))
	}
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

func createNewCertificate(appName, certFile, keyFile string) error {

	// create a keypair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	// get local hostname.
	host, _ := os.Hostname()

	// get local ip address.
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ua.BadCertificateInvalid
	}
	conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	// create a certificate.
	applicationURI, _ := url.Parse(fmt.Sprintf("urn:%s:%s", host, appName))
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subjectKeyHash := sha1.New()
	subjectKeyHash.Write(key.PublicKey.N.Bytes())
	subjectKeyId := subjectKeyHash.Sum(nil)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: appName},
		SubjectKeyId:          subjectKeyId,
		AuthorityKeyId:        subjectKeyId,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		IPAddresses:           []net.IP{localAddr.IP},
		URIs:                  []*url.URL{applicationURI},
	}

	rawcrt, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	if f, err := os.Create(certFile); err == nil {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: rawcrt}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	if f, err := os.Create(keyFile); err == nil {
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	return nil
}

func ensurePKI() error {

	// check if ./pki already exists
	if _, err := os.Stat("./pki"); !os.IsNotExist(err) {
		return nil
	}

	// make a pki directory, if not exist
	if err := os.MkdirAll("./pki", os.ModeDir|0755); err != nil {
		return err
	}

	// create a server cert in ./pki/server.crt
	if err := createNewCertificate("testserver", "./pki/server.crt", "./pki/server.key"); err != nil {
		return err
	}

	return nil
}
