// Copyright 2021 Converter Systems LLC. All rights reserved.

package timescaledb_test

import (
	"context"
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

	return srv, nil
}
