![robot][1]

# historian - [![Godoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/mod/github.com/awcullen/historian) [![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/awcullen/historian/master/LICENSE)
This package provides working examples of OPC UA servers that support storing and querying historical data.

## timescaledb
To create your own OPC UA server with historian services provided by TimescaleDB, start here [![Godoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/mod/github.com/awcullen/historian/timescaledb)

In this example, you will use Timescale, the open-source relational database for time-series and analytics.
https://www.timescale.com/

One way to install and run an instance of Timescale is to run this docker command:
docker run -d --name timescaledb -p 5432:5432 -e POSTGRES_PASSWORD=password timescale/timescaledb:latest-pg14

In file cmd\main.go, you will find a test server that simulates 12 dynamic process values.  The values are stored in the timescaledb instance.  

You can use UAExpert by Unified Automation to trend the historical values.

In file 'timescaledb_test.go', you will find client code that connects to the running server, queries the historical data, displaying both raw values and aggregated values.

The timescaledb example supports aggregation functions Avg, Min, Max and Count.

 [1]: robot6.jpg
