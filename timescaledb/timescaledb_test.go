// Copyright 2021 Converter Systems LLC. All rights reserved.

package timescaledb_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"

	"github.com/pkg/errors"
)

var (
	endpointURL = "opc.tcp://127.0.0.1:46010" // our testserver
)

// TestMain is run at the start of client testing. If an opcua server is not already running,
// then testserver is started.
func TestMain(m *testing.M) {
	if err := ensurePKI(); err != nil {
		fmt.Println(errors.Wrap(err, "Error creating pki"))
		os.Exit(1)
	}
	// check if server is listening at endpointURL
	_, err := client.FindServers(context.Background(), &ua.FindServersRequest{EndpointURL: endpointURL})
	if err != nil {
		// if a server is not listening, start our TestServer.
		srv, err := NewTestServer()
		if err != nil {
			fmt.Println(errors.Wrap(err, "Error constructing server"))
			os.Exit(2)
		}
		defer srv.Close()
		go func() {
			if err := srv.ListenAndServe(); err != ua.BadServerHalted {
				fmt.Println(errors.Wrap(err, "Error starting server"))
				os.Exit(3)
			}
		}()
	}
	// run the tests
	res := m.Run()
	defer os.Exit(res)
}

// TestReadHistory demonstrates reading history.
func TestReadHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long running test")
	}
	ctx := context.Background()
	ch, err := client.Dial(
		ctx,
		endpointURL,
		client.WithClientCertificateFile("./pki/client.crt", "./pki/client.key"),
		client.WithInsecureSkipVerify(), // skips verification of server certificate
		client.WithUserNameIdentity("root", "secret"),
	)
	if err != nil {
		t.Error(errors.Wrap(err, "Error opening client"))
		return
	}
	t.Logf("Success opening client: %s", ch.EndpointURL())

	t.Logf("Collecting 10 seconds of data...")
	time.Sleep(10 * time.Second)

	t.Log("Reading history for last 10 seconds")
	var cp ua.ByteString
	for {
		req2 := &ua.HistoryReadRequest{
			HistoryReadDetails: ua.ReadRawModifiedDetails{
				StartTime:        time.Now().Add(-10 * time.Second),
				EndTime:          time.Now(),
				NumValuesPerNode: 100,
				ReturnBounds:     false,
			},
			TimestampsToReturn:        ua.TimestampsToReturnBoth,
			ReleaseContinuationPoints: false,
			NodesToRead: []ua.HistoryReadValueID{
				{NodeID: ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.Double"), ContinuationPoint: cp},
			},
		}

		res2, err := ch.HistoryRead(ctx, req2)
		if err != nil {
			t.Error(errors.Wrap(err, "Error reading"))
			ch.Abort(ctx)
			return
		}

		if res2.Results[0].StatusCode.IsBad() {
			t.Errorf("Error reading values for node '%s'. %s", req2.NodesToRead[0].NodeID, res2.Results[0].StatusCode)
			ch.Abort(ctx)
			return
		}

		if historyData, ok := res2.Results[0].HistoryData.(ua.HistoryData); ok {
			t.Logf("Found %d value(s) for node '%s':", len(historyData.DataValues), req2.NodesToRead[0].NodeID)
			for _, result := range historyData.DataValues {
				t.Logf("Read %v, q: %#X, ts: %s", result.Value, uint32(result.StatusCode), result.SourceTimestamp)
			}
		}

		cp = res2.Results[0].ContinuationPoint
		if cp == "" {
			break
		}
	}
	t.Log("Now read the 2 sec average of the last 10 seconds...")

	req3 := &ua.HistoryReadRequest{
		HistoryReadDetails: ua.ReadProcessedDetails{
			StartTime:          time.Now().Add(-10 * time.Second),
			EndTime:            time.Now(),
			ProcessingInterval: 2000.0,
			AggregateType:      []ua.NodeID{ua.ObjectIDAggregateFunctionAverage},
		},
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: false,
		NodesToRead: []ua.HistoryReadValueID{
			{NodeID: ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.Double")},
		},
	}

	res3, err := ch.HistoryRead(ctx, req3)
	if err != nil {
		t.Error(errors.Wrap(err, "Error reading"))
		ch.Abort(ctx)
		return
	}

	if res3.Results[0].StatusCode.IsBad() {
		t.Errorf("Error reading values for node '%s'. %s", req3.NodesToRead[0].NodeID, res3.Results[0].StatusCode)
		ch.Abort(ctx)
		return
	}

	if historyData, ok := res3.Results[0].HistoryData.(ua.HistoryData); ok {
		t.Logf("Found %d average value(s) for node '%s':", len(historyData.DataValues), req3.NodesToRead[0].NodeID)
		for _, result := range historyData.DataValues {
			t.Logf("Read %v, q: %#X, ts: %s", result.Value, uint32(result.StatusCode), result.SourceTimestamp)
		}
	}

	ch.Close(ctx)
}

func createNewCertificate(appName, certFile, keyFile string) error {

	// Create a keypair.
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

	// Create a certificate.
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

	// create a client cert in ./pki
	if err := createNewCertificate("test-client", "./pki/client.crt", "./pki/client.key"); err != nil {
		return err
	}

	// create a server cert in ./pki
	if err := createNewCertificate("testserver", "./pki/server.crt", "./pki/server.key"); err != nil {
		return err
	}
	return nil
}
