// Copyright 2021 Converter Systems LLC. All rights reserved.

package timescaledb_test

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"math"
	math_rand "math/rand"
	"os"
	"time"

	"github.com/awcullen/historian/timescaledb"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
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
	//go:embed testnodeset_test.xml
	testnodeset []byte
)

func NewTestServer() (*server.Server, error) {

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
			DiscoveryURLs:       []string{fmt.Sprintf("opc.tcp://%s:%d", host, port)},
		},
		"./pki/server.crt",
		"./pki/server.key",
		fmt.Sprintf("opc.tcp://%s:%d", host, port),
		server.WithBuildInfo(
			ua.BuildInfo{
				ProductURI:       "http://github.com/awcullen/opcua",
				ManufacturerName: "awcullen",
				ProductName:      "testserver",
				SoftwareVersion:  SoftwareVersion,
			}),
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
		server.WithAnonymousIdentity(true),
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
		server.WithHistorian(historian),
	)
	if err != nil {
		return nil, err
	}

	// load nodeset
	nm := srv.NamespaceManager()
	if err := nm.LoadNodeSetFromBuffer(testnodeset); err != nil {
		return nil, err
	}

	// install MethodNoArgs method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.Methods.MethodNoArgs")); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req ua.CallMethodRequest) ua.CallMethodResult {
			return ua.CallMethodResult{}
		})
	}

	// install MethodI method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.Methods.MethodI")); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req ua.CallMethodRequest) ua.CallMethodResult {
			if len(req.InputArguments) < 1 {
				return ua.CallMethodResult{StatusCode: ua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 1 {
				return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
			}
			statusCode := ua.Good
			inputArgumentResults := make([]ua.StatusCode, 1)
			_, ok := req.InputArguments[0].(uint32)
			if !ok {
				statusCode = ua.BadInvalidArgument
				inputArgumentResults[0] = ua.BadTypeMismatch
			}
			if statusCode == ua.BadInvalidArgument {
				return ua.CallMethodResult{StatusCode: statusCode, InputArgumentResults: inputArgumentResults}
			}
			return ua.CallMethodResult{OutputArguments: []ua.Variant{}}
		})
	}

	// install MethodO method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.Methods.MethodO")); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req ua.CallMethodRequest) ua.CallMethodResult {
			if len(req.InputArguments) > 0 {
				return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
			}
			result := uint32(42)
			return ua.CallMethodResult{OutputArguments: []ua.Variant{uint32(result)}}
		})
	}

	// install MethodIO method
	if n, ok := nm.FindMethod(ua.ParseNodeID("ns=2;s=Demo.Methods.MethodIO")); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req ua.CallMethodRequest) ua.CallMethodResult {
			if len(req.InputArguments) < 2 {
				return ua.CallMethodResult{StatusCode: ua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 2 {
				return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
			}
			statusCode := ua.Good
			inputArgumentResults := make([]ua.StatusCode, 2)
			a, ok := req.InputArguments[0].(uint32)
			if !ok {
				statusCode = ua.BadInvalidArgument
				inputArgumentResults[0] = ua.BadTypeMismatch
			}
			b, ok := req.InputArguments[1].(uint32)
			if !ok {
				statusCode = ua.BadInvalidArgument
				inputArgumentResults[1] = ua.BadTypeMismatch
			}
			if statusCode == ua.BadInvalidArgument {
				return ua.CallMethodResult{StatusCode: statusCode, InputArgumentResults: inputArgumentResults}
			}
			result := a + b
			return ua.CallMethodResult{OutputArguments: []ua.Variant{uint32(result)}}
		})
	}

	// Simulate process variables changing every second. Server stores values in historian.
	go func() {
		DemoDynamicScalarBool, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.Bool"))
		DemoDynamicScalarByte, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.Byte"))
		DemoDynamicScalarDouble, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.Double"))
		DemoDynamicScalarFloat, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.Float"))
		DemoDynamicScalarInt16, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.Int16"))
		DemoDynamicScalarInt32, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.Int32"))
		DemoDynamicScalarInt64, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.Int64"))
		DemoDynamicScalarSByte, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.SByte"))
		DemoDynamicScalarUInt16, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.UInt16"))
		DemoDynamicScalarUInt32, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.UInt32"))
		DemoDynamicScalarUInt64, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.UInt64"))
		DemoDynamicScalarString, _ := nm.FindVariable(ua.ParseNodeID("ns=2;s=Demo.Dynamic.Scalar.String"))
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				DemoDynamicScalarBool.SetValue(ua.NewDataValue(bool(math_rand.Intn(10) >= 5), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarByte.SetValue(ua.NewDataValue(byte(math_rand.Intn(math.MaxUint8)), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarDouble.SetValue(ua.NewDataValue(math_rand.Float64(), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarFloat.SetValue(ua.NewDataValue(float32(math_rand.Float64()), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarInt16.SetValue(ua.NewDataValue(int16(math_rand.Intn(math.MaxInt16)), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarInt32.SetValue(ua.NewDataValue(int32(math_rand.Intn(math.MaxInt32)), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarInt64.SetValue(ua.NewDataValue(int64(math_rand.Intn(math.MaxInt64)), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarSByte.SetValue(ua.NewDataValue(int8(math_rand.Intn(math.MaxInt8)), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarUInt16.SetValue(ua.NewDataValue(uint16(math_rand.Intn(math.MaxInt16)), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarUInt32.SetValue(ua.NewDataValue(uint32(math_rand.Intn(math.MaxInt32)), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarUInt64.SetValue(ua.NewDataValue(uint64(math_rand.Intn(math.MaxInt64)), 0, time.Now(), 0, time.Now(), 0))
				DemoDynamicScalarString.SetValue(ua.NewDataValue(time.Now().Format(time.StampMilli), 0, time.Now(), 0, time.Now(), 0))
			case <-srv.Closing():
				return
			}
		}
	}()

	return srv, nil
}
