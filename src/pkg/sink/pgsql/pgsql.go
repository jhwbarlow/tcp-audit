package pgsql

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v4"
	"github.com/jhwbarlow/tcp-audit/pkg/event"
)

const (
	tableCreateSQL = `
CREATE TABLE tcp_events (
	uid         TEXT PRIMARY KEY,
	timestamp   TIMESTAMP,
	pid_on_cpu  INTEGER,
	comm_on_cpu TEXT,
	src_ip      INET,
	dst_ip      INET,
	src_port    INTEGER,
	dst_port    INTEGER,
	old_state   TEXT,
	new_state   TEXT
)`

	insertSQL = `
INSERT INTO tcp_events (
	uid,
	timestamp,  
	pid_on_cpu,
	comm_on_cpu,
	src_ip,
	dst_ip,
	src_port,
	dst_port,
	old_state,
	new_state
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	insertSQLStmtName = "tcp_events_insert"
)

type Sinker struct {
	conn       *pgx.Conn
	insertStmt *pgconn.StatementDescription
}

func New() (*Sinker, error) {
	conn, err := connect()
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	if err := createTable(conn, tableCreateSQL); err != nil {
		return nil, fmt.Errorf("creating tcp_events table: %w", err)
	}

	insertStmt, err := prepareStatement(conn, insertSQL, insertSQLStmtName)
	if err != nil {
		return nil, fmt.Errorf("preparing insert statement: %w", err)
	}

	return &Sinker{
		conn:       conn,
		insertStmt: insertStmt,
	}, nil
}

func (s *Sinker) Sink(event *event.Event) error {
	uid := uuid.NewString()
	time := event.Time
	pid := event.PIDOnCPU
	comm := event.CommandOnCPU
	srcIP := event.SourceIP
	dstIP := event.DestIP
	srcPort := event.SourcePort
	dstPort := event.DestPort
	oldState := event.OldState.String()
	newState := event.NewState.String()

	if _, err := s.conn.Exec(context.TODO(),
		insertSQLStmtName,
		uid,
		time,
		pid,
		comm,
		srcIP,
		dstIP,
		srcPort,
		dstPort,
		oldState,
		newState); err != nil {
		return fmt.Errorf("inserting event: %w", err)
	}

	return nil
}

func (s *Sinker) Close() error {
	log.Printf("Closing database connection: %s:%d",
		s.conn.Config().Host,
		s.conn.Config().Port)
	if err := s.conn.Close(context.TODO()); err != nil {
		return fmt.Errorf("closing connection: %w", err)
	}

	return nil
}

func connect() (*pgx.Conn, error) {
	conn, err := pgx.Connect(context.TODO(), "postgresql://postgres:mysecretpassword@127.0.0.1/postgres")
	if err != nil {
		return nil, fmt.Errorf("establishing connection to database: %w", err)
	}

	return conn, nil
}

func createTable(conn *pgx.Conn, sql string) error {
	if _, err := conn.Exec(context.TODO(), sql); err != nil {
		if err, ok := err.(*pgconn.PgError); ok && err.Code == pgerrcode.DuplicateTable {
			// Table already created - nothing to do!
			return nil
		}

		return fmt.Errorf("creating table: %w", err)
	}

	return nil
}

func prepareStatement(conn *pgx.Conn, sql, name string) (*pgconn.StatementDescription, error) {
	stmt, err := conn.Prepare(context.TODO(), name, sql)
	if err != nil {
		return nil, fmt.Errorf("preparing statement: %w", err)
	}

	return stmt, nil
}
