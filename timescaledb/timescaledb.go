// Copyright 2021 Converter Systems LLC. All rights reserved.

// Package timescaledb supports adding history services to an OPC UA server using Postgres with TimeScaleDb addin.
package timescaledb

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	// this import loads "pgx" driver for postgres
	_ "github.com/jackc/pgx/stdlib"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

/*
docker run -d --name timescaledb -p 5432:5432 -e POSTGRES_PASSWORD=password timescale/timescaledb:latest-pg14
*/

var (
	pgTimestamptzSecondFormat = "2006-01-02 15:04:05.999999999Z07:00:00"
	uaMinDateTime             = time.Unix(-11644473600, 0).UTC()
)

// Historian represents the connection to historian service.
type Historian struct {
	sync.RWMutex
	db          *sql.DB
	insertStmts map[string]*sql.Stmt
}

// Open connects to a historian service.
func Open(ctx context.Context, connectionURI string, databaseName string) (*Historian, error) {
	db, err := sql.Open("pgx", connectionURI+"/"+databaseName)
	if err == nil {
		err = db.PingContext(ctx)
	}
	if err != nil {
		// if not exist, try creating database
		db, err = sql.Open("pgx", connectionURI)
		if err != nil {
			return nil, err
		}
		_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s;", databaseName))
		if err != nil {
			return nil, err
		}
		db.Close()
		db, err = sql.Open("pgx", connectionURI+"/"+databaseName)
		if err != nil {
			return nil, err
		}
		_, err = db.Exec("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")
		if err != nil {
			return nil, err
		}
		_, err = db.Exec("CREATE TABLE catalog (nodeid text NOT NULL, tablename text NOT NULL);")
		if err != nil {
			return nil, err
		}
		var tables = []struct {
			tablename string
			datatype  string
		}{
			{"_bool", "boolean"},
			{"_int16", "smallint"},
			{"_int32", "integer"},
			{"_int64", "bigint"},
			{"_float32", "real"},
			{"_float64", "double precision"},
			{"_string", "text"},
			{"_time", "timestamp with time zone"},
			{"_uuid", "uuid"},
			{"_bytestring", "bytea"},
			{"_xml", "xml"},
		}
		for _, v := range tables {
			_, err = db.Exec(fmt.Sprintf(`
			CREATE TABLE "%s"
			(
				id text NOT NULL,
				v %s NOT NULL,
				q integer NOT NULL,
				t timestamp with time zone NOT NULL,
				ismodified boolean NOT NULL,
				isdeleted boolean NOT NULL
			);
			SELECT create_hypertable('%s', 't');`, v.tablename, v.datatype, v.tablename))
			if err != nil {
				return nil, err
			}
		}
	}
	h := &Historian{}
	h.insertStmts = make(map[string]*sql.Stmt)
	h.db = db
	return h, nil
}

// Close disconnects from a historian service.
func (h *Historian) Close(ctx context.Context) error {
	if h.db != nil {
		return h.db.Close()
	}
	return nil
}

// WriteEvent writes the event to storage.
func (h *Historian) WriteEvent(ctx context.Context, nodeID ua.NodeID, eventFields []ua.Variant) error {
	return ua.BadHistoryOperationUnsupported
}

// WriteValue writes the value to storage.
func (h *Historian) WriteValue(ctx context.Context, nodeID ua.NodeID, value ua.DataValue) error {
	if h == nil || h.db == nil {
		return ua.BadHistoryOperationUnsupported
	}
	id := fmt.Sprint(nodeID)
	insertStmt := h.insertStmts[id]
	if insertStmt == nil {
		tablename, err := h.getOrAddTable(ctx, nodeID, value)
		if err != nil {
			return err
		}
		insertStmt, err = h.db.PrepareContext(ctx, fmt.Sprintf(`INSERT INTO "%s" (id, v, q, t, ismodified, isdeleted) VALUES ($1, $2, $3, $4, false, false);`, tablename))
		if err != nil {
			return err
		}
		h.insertStmts[id] = insertStmt
	}
	ts := value.SourceTimestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	_, err := insertStmt.ExecContext(ctx, id, value.Value, int32(value.StatusCode), ts)
	return err
}

// ReadEvent reads the events from storage
func (h *Historian) ReadEvent(ctx context.Context, nodesToRead []ua.HistoryReadValueID, details ua.ReadEventDetails, timestampsToReturn ua.TimestampsToReturn, releaseContinuationPoints bool) ([]ua.HistoryReadResult, ua.StatusCode) {
	return nil, ua.BadHistoryOperationUnsupported
}

// ReadRawModified reads the raw or modified values from storage
func (h *Historian) ReadRawModified(ctx context.Context, nodesToRead []ua.HistoryReadValueID, details ua.ReadRawModifiedDetails, timestampsToReturn ua.TimestampsToReturn, releaseContinuationPoints bool) ([]ua.HistoryReadResult, ua.StatusCode) {
	if h == nil || h.db == nil {
		return nil, ua.BadHistoryOperationUnsupported
	}
	// get the server's namespace manager
	session, ok := ctx.Value(server.SessionKey).(*server.Session)
	if !ok {
		return nil, ua.BadHistoryOperationUnsupported
	}
	nm := session.Server().NamespaceManager()
	// prepare the results
	results := make([]ua.HistoryReadResult, len(nodesToRead))
	// for each node in nodesToRead, read the raw or modified values from storage, and return in results.
Outer:
	for i := 0; i < len(nodesToRead); i++ {
		nodeToRead := nodesToRead[i]
		// if releaseContinuationPoints, remove it from cache, and return no data.
		if releaseContinuationPoints {
			if nodeToRead.ContinuationPoint == "" {
				results[i] = ua.HistoryReadResult{StatusCode: ua.GoodNoData, HistoryData: &ua.HistoryData{DataValues: []ua.DataValue{}}}
				continue
			}
			if _, ok := h.removeContinuationPoint(nodeToRead.ContinuationPoint); ok {
				results[i] = ua.HistoryReadResult{StatusCode: ua.GoodNoData, HistoryData: &ua.HistoryData{DataValues: []ua.DataValue{}}}
				continue
			}
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadContinuationPointInvalid}
			continue
		}
		// reading ranges out of slices is not implemented
		if nodeToRead.IndexRange != "" {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadNotImplemented}
			continue
		}
		// reading modified data is not implemented
		if details.IsReadModified {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadNotImplemented}
			continue
		}
		n2, ok := nm.FindVariable(nodeToRead.NodeID)
		if !ok {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadNodeIDUnknown}
			continue
		}
		// check if read history permitted
		rp := n2.UserRolePermissions(ctx)
		if !server.IsUserPermitted(rp, ua.PermissionTypeReadHistory) {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadUserAccessDenied}
			continue
		}

		var (
			v           interface{}
			q           int32
			t           time.Time
			query       string
			pageResults bool
			values      []ua.DataValue
		)
		id := fmt.Sprint(nodeToRead.NodeID)
		tablename, err := h.getTable(ctx, nodeToRead.NodeID)
		if err != nil {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
			continue
		}
		query = fmt.Sprintf(`SELECT v, q, t FROM %s WHERE id = '%s'`, tablename, id)

		if details.StartTime.After(uaMinDateTime) {
			if details.EndTime.After(uaMinDateTime) {
				pageResults = details.NumValuesPerNode > 0
				if cp := nodeToRead.ContinuationPoint; cp != "" {
					// with continuation point
					cpStartTime, ok := h.removeContinuationPoint(cp)
					if !ok {
						results[i] = ua.HistoryReadResult{StatusCode: ua.BadContinuationPointInvalid}
						continue
					}
					if details.EndTime.Before(details.StartTime) {
						query += fmt.Sprintf(` AND t >= '%s'`, details.EndTime.Format(pgTimestamptzSecondFormat))
						query += fmt.Sprintf(` AND t < '%s'`, cpStartTime.Format(pgTimestamptzSecondFormat))
						query += " ORDER BY t DESC"
					} else {
						query += fmt.Sprintf(` AND t > '%s'`, cpStartTime.Format(pgTimestamptzSecondFormat))
						query += fmt.Sprintf(` AND t <= '%s'`, details.EndTime.Format(pgTimestamptzSecondFormat))
						query += " ORDER BY t ASC"
					}
				} else {
					// without continuation point
					if details.EndTime.Before(details.StartTime) {
						query += fmt.Sprintf(` AND t >= '%s'`, details.EndTime.Format(pgTimestamptzSecondFormat))
						query += fmt.Sprintf(` AND t < '%s'`, details.StartTime.Format(pgTimestamptzSecondFormat))
						query += " ORDER BY t DESC"
					} else {
						query += fmt.Sprintf(` AND t > '%s'`, details.StartTime.Format(pgTimestamptzSecondFormat))
						query += fmt.Sprintf(` AND t <= '%s'`, details.EndTime.Format(pgTimestamptzSecondFormat))
						query += " ORDER BY t ASC"
					}
				}
			} else {
				// start is specified, end is nil
				if details.NumValuesPerNode == 0 {
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadInvalidArgument}
					continue
				}
				query += fmt.Sprintf(` AND t > '%s'`, details.StartTime.Format(pgTimestamptzSecondFormat))
				query += " ORDER BY t ASC"
			}
		} else {
			if details.EndTime.After(uaMinDateTime) {
				// start is nil, end is specified
				if details.NumValuesPerNode == 0 {
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadInvalidArgument}
					continue
				}
				query += fmt.Sprintf(` AND t < '%s'`, details.EndTime.Format(pgTimestamptzSecondFormat))
				query += " ORDER BY t DESC"
			} else {
				// start is nil, end is nil
				results[i] = ua.HistoryReadResult{StatusCode: ua.BadInvalidArgument}
				continue
			}
		}

		if details.NumValuesPerNode > 0 {
			query += fmt.Sprintf(` LIMIT %d`, details.NumValuesPerNode)
		}

		query += ";"

		rows, err := h.db.Query(query)
		if err != nil {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
			continue
		}
		defer rows.Close()

		if timestampsToReturn == ua.TimestampsToReturnBoth {
			for rows.Next() {
				err := rows.Scan(&v, &q, &t)
				if err != nil {
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue Outer
				}
				values = append(values, ua.NewDataValue(v, ua.StatusCode(q), t, 0, t, 0))
			}
		} else {
			for rows.Next() {
				err := rows.Scan(&v, &q, &t)
				if err != nil {
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue Outer
				}
				values = append(values, ua.NewDataValue(v, ua.StatusCode(q), t, 0, time.Time{}, 0))
			}
		}
		err = rows.Err()
		if err != nil {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
			continue
		}
		if num := int(details.NumValuesPerNode); pageResults && num == len(values) {
			// add continuation point
			cp, err := h.addContinuationPoint(values[num-1].SourceTimestamp)
			if err != nil {
				results[i] = ua.HistoryReadResult{StatusCode: ua.BadNoContinuationPoints}
				continue
			}
			results[i] = ua.HistoryReadResult{HistoryData: &ua.HistoryData{DataValues: values}, ContinuationPoint: cp}
			continue
		}
		if len(values) > 0 {
			results[i] = ua.HistoryReadResult{HistoryData: &ua.HistoryData{DataValues: values}}
			continue
		}
		results[i] = ua.HistoryReadResult{StatusCode: ua.GoodNoData, HistoryData: &ua.HistoryData{DataValues: values}}
		continue
	}
	return results, ua.Good
}

// ReadProcessed reads the aggregated values from storage
func (h *Historian) ReadProcessed(ctx context.Context, nodesToRead []ua.HistoryReadValueID, details ua.ReadProcessedDetails, timestampsToReturn ua.TimestampsToReturn, releaseContinuationPoints bool) ([]ua.HistoryReadResult, ua.StatusCode) {
	if h == nil || h.db == nil {
		return nil, ua.BadHistoryOperationUnsupported
	}
	// check if there is an AggregateType specified for each nodeToRead
	if details.AggregateType == nil || len(details.AggregateType) != len(nodesToRead) {
		return nil, ua.BadAggregateListMismatch
	}
	// get the server's namespace manager
	session, ok := ctx.Value(server.SessionKey).(*server.Session)
	if !ok {
		return nil, ua.BadHistoryOperationUnsupported
	}
	nm := session.Server().NamespaceManager()
	// prepare the results
	results := make([]ua.HistoryReadResult, len(nodesToRead))
	// for each node in nodesToRead, read the raw or modified values from storage, and return in results.
Outer:
	for i := 0; i < len(nodesToRead); i++ {
		nodeToRead := nodesToRead[i]
		// if releaseContinuationPoints, remove it from cache, and return no data.
		if releaseContinuationPoints {
			if nodeToRead.ContinuationPoint == "" {
				results[i] = ua.HistoryReadResult{StatusCode: ua.GoodNoData, HistoryData: &ua.HistoryData{DataValues: []ua.DataValue{}}}
				continue
			}
			if _, ok := h.removeContinuationPoint(nodeToRead.ContinuationPoint); ok {
				results[i] = ua.HistoryReadResult{StatusCode: ua.GoodNoData, HistoryData: &ua.HistoryData{DataValues: []ua.DataValue{}}}
				continue
			}
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadContinuationPointInvalid}
			continue
		}
		// reading ranges out of slices is not implemented
		if nodeToRead.IndexRange != "" {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadNotImplemented}
			continue
		}
		// if !details.AggregateConfiguration.UseServerCapabilitiesDefaults {
		// 	results[i] = ua.HistoryReadResult{StatusCode: ua.BadAggregateConfigurationRejected}
		//  continue
		// }
		n2, ok := nm.FindVariable(nodeToRead.NodeID)
		if !ok {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadNodeIDUnknown}
			continue
		}
		// check if read history permitted
		rp := n2.UserRolePermissions(ctx)
		if !server.IsUserPermitted(rp, ua.PermissionTypeReadHistory) {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadUserAccessDenied}
			continue
		}
		var (
			v      interface{}
			q      int32
			t      time.Time
			query  string
			values []ua.DataValue
		)

		id := fmt.Sprint(nodeToRead.NodeID)
		tablename, err := h.getTable(ctx, nodeToRead.NodeID)
		if err != nil {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
			continue
		}

		if details.StartTime.Equal(details.EndTime) || details.ProcessingInterval < 0.0 {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadInvalidArgument}
			continue
		}

		query = `WITH timeseries_data AS (`

		if details.EndTime.Before(details.StartTime) {
			// from start to end, descending
			pi := int64(details.ProcessingInterval)
			if details.ProcessingInterval == 0.0 {
				pi = int64(details.StartTime.Sub(details.EndTime).Seconds() * 1000.0)
			}
			interval := fmt.Sprintf(`'%d milliseconds'`, pi)
			start := fmt.Sprintf(`TIMESTAMPTZ '%s'`, details.StartTime.Format(pgTimestamptzSecondFormat))
			end := fmt.Sprintf(`TIMESTAMPTZ '%s'`, details.EndTime.Format(pgTimestamptzSecondFormat))
			switch details.AggregateType[i] {
			case ua.ObjectIDAggregateFunctionAverage:
				vt := nm.FindVariantType(n2.DataType())
				switch vt {
				case ua.VariantTypeSByte, ua.VariantTypeByte, ua.VariantTypeInt16, ua.VariantTypeUInt16:
				case ua.VariantTypeInt32, ua.VariantTypeUInt32:
				case ua.VariantTypeInt64, ua.VariantTypeUInt64:
				case ua.VariantTypeFloat:
				case ua.VariantTypeDouble:
				default:
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue
				}
				query += fmt.Sprintf(`SELECT AVG(v) AS v1, X'401'::int AS q1, time_bucket(%s, t, %s) + %s AS t1 FROM %s WHERE id = '%s'`, interval, start, interval, tablename, id)
			case ua.ObjectIDAggregateFunctionMinimum:
				vt := nm.FindVariantType(n2.DataType())
				switch vt {
				case ua.VariantTypeSByte, ua.VariantTypeByte, ua.VariantTypeInt16, ua.VariantTypeUInt16:
				case ua.VariantTypeInt32, ua.VariantTypeUInt32:
				case ua.VariantTypeInt64, ua.VariantTypeUInt64:
				case ua.VariantTypeFloat:
				case ua.VariantTypeDouble:
				default:
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue
				}
				query += fmt.Sprintf(`SELECT MIN(v) AS v1, X'401'::int AS q1, time_bucket(%s, t, %s) + %s AS t1 FROM %s WHERE id = '%s'`, interval, start, interval, tablename, id)
			case ua.ObjectIDAggregateFunctionMaximum:
				vt := nm.FindVariantType(n2.DataType())
				switch vt {
				case ua.VariantTypeSByte, ua.VariantTypeByte, ua.VariantTypeInt16, ua.VariantTypeUInt16:
				case ua.VariantTypeInt32, ua.VariantTypeUInt32:
				case ua.VariantTypeInt64, ua.VariantTypeUInt64:
				case ua.VariantTypeFloat:
				case ua.VariantTypeDouble:
				default:
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue
				}
				query += fmt.Sprintf(`SELECT MAX(v) AS v1, X'401'::int AS q1, time_bucket(%s, t, %s) + %s AS t1 FROM %s WHERE id = '%s'`, interval, start, interval, tablename, id)
			case ua.ObjectIDAggregateFunctionCount:
				vt := nm.FindVariantType(n2.DataType())
				switch vt {
				case ua.VariantTypeSByte, ua.VariantTypeByte, ua.VariantTypeInt16, ua.VariantTypeUInt16:
				case ua.VariantTypeInt32, ua.VariantTypeUInt32:
				case ua.VariantTypeInt64, ua.VariantTypeUInt64:
				case ua.VariantTypeFloat:
				case ua.VariantTypeDouble:
				default:
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue
				}
				query += fmt.Sprintf(`SELECT COUNT(v) AS v1, X'401'::int AS q1, time_bucket(%s, t, %s) + %s AS t1 FROM %s WHERE id = '%s'`, interval, start, interval, tablename, id)
			default:
				results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
				continue
			}
			query += fmt.Sprintf(` AND t <= %s`, start)
			query += fmt.Sprintf(` AND t > %s`, end)
			query += ` GROUP BY t1 UNION SELECT null v1, X'809B0000'::int q1, gs1 t1`
			query += fmt.Sprintf(` FROM generate_series(%s, %s + '1 milliseconds', '-%d milliseconds') as gs1`, start, end, pi)
			query += `) SELECT DISTINCT ON (td1.t1) td1.v1, td1.q1, td1.t1 FROM timeseries_data td1 ORDER BY td1.t1 DESC, td1.q1 DESC;`

		} else {
			// from start to end, ascending
			pi := int64(details.ProcessingInterval)
			if details.ProcessingInterval == 0.0 {
				pi = int64(details.EndTime.Sub(details.StartTime).Seconds() * 1000.0)
			}
			interval := fmt.Sprintf(`'%d milliseconds'`, pi)
			start := fmt.Sprintf(`TIMESTAMPTZ '%s'`, details.StartTime.Format(pgTimestamptzSecondFormat))
			end := fmt.Sprintf(`TIMESTAMPTZ '%s'`, details.EndTime.Format(pgTimestamptzSecondFormat))
			switch details.AggregateType[i] {
			case ua.ObjectIDAggregateFunctionAverage:
				vt := nm.FindVariantType(n2.DataType())
				switch vt {
				case ua.VariantTypeSByte, ua.VariantTypeByte, ua.VariantTypeInt16, ua.VariantTypeUInt16:
				case ua.VariantTypeInt32, ua.VariantTypeUInt32:
				case ua.VariantTypeInt64, ua.VariantTypeUInt64:
				case ua.VariantTypeFloat:
				case ua.VariantTypeDouble:
				default:
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue
				}
				query += fmt.Sprintf(`SELECT AVG(v) AS v1, X'401'::int AS q1, time_bucket(%s, t, %s) AS t1 FROM %s WHERE id = '%s'`, interval, start, tablename, id)
			case ua.ObjectIDAggregateFunctionMinimum:
				vt := nm.FindVariantType(n2.DataType())
				switch vt {
				case ua.VariantTypeSByte, ua.VariantTypeByte, ua.VariantTypeInt16, ua.VariantTypeUInt16:
				case ua.VariantTypeInt32, ua.VariantTypeUInt32:
				case ua.VariantTypeInt64, ua.VariantTypeUInt64:
				case ua.VariantTypeFloat:
				case ua.VariantTypeDouble:
				default:
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue
				}
				query += fmt.Sprintf(`SELECT MIN(v) AS v1, X'401'::int AS q1, time_bucket(%s, t, %s) AS t1 FROM %s WHERE id = '%s'`, interval, start, tablename, id)
			case ua.ObjectIDAggregateFunctionMaximum:
				vt := nm.FindVariantType(n2.DataType())
				switch vt {
				case ua.VariantTypeSByte, ua.VariantTypeByte, ua.VariantTypeInt16, ua.VariantTypeUInt16:
				case ua.VariantTypeInt32, ua.VariantTypeUInt32:
				case ua.VariantTypeInt64, ua.VariantTypeUInt64:
				case ua.VariantTypeFloat:
				case ua.VariantTypeDouble:
				default:
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue
				}
				query += fmt.Sprintf(`SELECT MAX(v) AS v1, X'401'::int AS q1, time_bucket(%s, t, %s) AS t1 FROM %s WHERE id = '%s'`, interval, start, tablename, id)
			case ua.ObjectIDAggregateFunctionCount:
				vt := nm.FindVariantType(n2.DataType())
				switch vt {
				case ua.VariantTypeSByte, ua.VariantTypeByte, ua.VariantTypeInt16, ua.VariantTypeUInt16:
				case ua.VariantTypeInt32, ua.VariantTypeUInt32:
				case ua.VariantTypeInt64, ua.VariantTypeUInt64:
				case ua.VariantTypeFloat:
				case ua.VariantTypeDouble:
				default:
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue
				}
				query += fmt.Sprintf(`SELECT COUNT(v) AS v1, X'401'::int AS q1, time_bucket(%s, t, %s) AS t1 FROM %s WHERE id = '%s'`, interval, start, tablename, id)
			default:
				results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
				continue
			}
			query += fmt.Sprintf(` AND t >= %s`, start)
			query += fmt.Sprintf(` AND t < %s`, end)
			query += ` GROUP BY t1 UNION SELECT null v1, X'809B0000'::int q1, gs1 t1`
			query += fmt.Sprintf(` FROM generate_series(%s, %s + '-1 milliseconds', %s) as gs1`, start, end, interval)
			query += `) SELECT DISTINCT ON (td1.t1) td1.v1, td1.q1, td1.t1 FROM timeseries_data td1 ORDER BY td1.t1 ASC, td1.q1 DESC;`
		}

		rows, err := h.db.Query(query)
		if err != nil {
			results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
			continue
		}
		defer rows.Close()

		if timestampsToReturn == ua.TimestampsToReturnBoth {
			for rows.Next() {
				err := rows.Scan(&v, &q, &t)
				if err != nil {
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue Outer
				}
				values = append(values, ua.NewDataValue(v, ua.StatusCode(q), t, 0, t, 0))
			}
		} else {
			for rows.Next() {
				err := rows.Scan(&v, &q, &t)
				if err != nil {
					results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
					continue Outer
				}
				values = append(values, ua.NewDataValue(v, ua.StatusCode(q), t, 0, time.Time{}, 0))
			}
			err = rows.Err()
			if err != nil {
				results[i] = ua.HistoryReadResult{StatusCode: ua.BadHistoryOperationUnsupported}
				continue
			}

		}

		if len(values) > 0 {
			results[i] = ua.HistoryReadResult{HistoryData: &ua.HistoryData{DataValues: values}}
			continue
		}
		results[i] = ua.HistoryReadResult{StatusCode: ua.GoodNoData, HistoryData: &ua.HistoryData{DataValues: values}}
		continue
	}
	return results, ua.Good
}

// ReadAtTime reads the associated values from storage
func (h *Historian) ReadAtTime(ctx context.Context, nodesToRead []ua.HistoryReadValueID, details ua.ReadAtTimeDetails, timestampsToReturn ua.TimestampsToReturn, releaseContinuationPoints bool) ([]ua.HistoryReadResult, ua.StatusCode) {
	return nil, ua.BadHistoryOperationUnsupported
}

// getOrAddTable returns the table name for the NodeID, or adds a new table if history for the NodeID does not exist.
func (h *Historian) getOrAddTable(ctx context.Context, nodeid ua.NodeID, value ua.DataValue) (string, error) {
	if h == nil {
		return "", ua.BadUnexpectedError
	}
	if nodeid == nil {
		return "", ua.BadUnexpectedError
	}
	// get or add to catalog
	id := fmt.Sprint(nodeid)
	tablename := ""
	err := h.db.QueryRow("SELECT tablename FROM catalog WHERE nodeid = $1", id).Scan(&tablename)
	if err == sql.ErrNoRows {
		// get the tablename from the data type
		switch value.Value.(type) {
		case bool:
			tablename = "_bool"
		case int8, uint8, int16, uint16:
			tablename = "_int16"
		case int32, uint32:
			tablename = "_int32"
		case int64, uint64:
			tablename = "_int64"
		case float32:
			tablename = "_float32"
		case float64:
			tablename = "_float64"
		case string:
			tablename = "_string"
		case time.Time:
			tablename = "_time"
		case uuid.UUID:
			tablename = "_uuid"
		case ua.ByteString:
			tablename = "_bytestring"
		case ua.XMLElement:
			tablename = "_xml"
		default:
			return "", ua.BadUnexpectedError
		}
		_, err = h.db.Exec("INSERT INTO catalog (nodeid, tablename) VALUES ($1, $2);", id, tablename)
		if err != nil {
			return "", ua.BadUnexpectedError
		}
		return tablename, nil
	}
	if err != nil {
		return "", ua.BadUnexpectedError
	}
	return tablename, nil
}

// getTable returns the table name for the NodeID, or error if history for the NodeID does not exist.
func (h *Historian) getTable(ctx context.Context, nodeid ua.NodeID) (string, error) {
	if h == nil {
		return "", ua.BadUnexpectedError
	}
	if nodeid == nil {
		return "", ua.BadUnexpectedError
	}
	// get from catalog
	id := fmt.Sprint(nodeid)
	tablename := ""
	err := h.db.QueryRow("SELECT tablename FROM catalog WHERE nodeid = $1", id).Scan(&tablename)
	if err != nil {
		return "", ua.BadUnexpectedError
	}
	return tablename, nil
}

func (h *Historian) addContinuationPoint(t time.Time) (ua.ByteString, error) {
	bs, err := t.MarshalBinary()
	if err != nil {
		return "", err
	}
	return ua.ByteString(bs), nil
}

func (h *Historian) removeContinuationPoint(cp ua.ByteString) (time.Time, bool) {
	t := time.Time{}
	if err := t.UnmarshalBinary([]byte(cp)); err != nil {
		return time.Time{}, false
	}
	return t, true
}
