package mariadbstore

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type MariadbStore struct {
	db               *sql.DB
	databaseName     string
	tableName        string
	insertStmt       *sql.Stmt
	updateStmt       *sql.Stmt
	selectStmt       *sql.Stmt
	selectAllStmt    *sql.Stmt
	deleteStmt       *sql.Stmt
	Codecs           []securecookie.Codec
	Options          *sessions.Options
	stopChan         chan struct{}
	doneStoppingChan chan struct{}
}

func NewMariadbStore(db *sql.DB, databaseName, tableName string, keyPairs ...[]byte) (*MariadbStore, error) {
	if db == nil {
		return nil, errors.New("db cannot be nil")
	}

	createDatabaseQuery := fmt.Sprintf(`CREATE DATABASE IF NOT EXISTS %s`, databaseName)
	if _, err := db.Exec(createDatabaseQuery); err != nil {
		return nil, err
	}

	createTableQuery := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
			expires INT NOT NULL,
			session_data LONGBLOB
		) ENGINE=InnoDB;
	`, tableName)
	if _, err := db.Exec(createTableQuery); err != nil {
		return nil, err
	}

	insertStmt, err := db.Prepare(fmt.Sprintf(`INSERT INTO %s.%s SET expires=?, session_data=?`, databaseName, tableName))
	if err != nil {
		return nil, err
	}

	updateStmt, err := db.Prepare(fmt.Sprintf(`UPDATE %s.%s SET expires=?, session_data=?`, databaseName, tableName))
	if err != nil {
		return nil, err
	}

	selectStmt, err := db.Prepare(fmt.Sprintf(`SELECT session_data FROM %s.%s WHERE id=?`, databaseName, tableName))
	if err != nil {
		return nil, err
	}

	selectAllStmt, err := db.Prepare(fmt.Sprintf(`SELECT id, expires FROM %s.%s`, databaseName, tableName))
	if err != nil {
		return nil, err
	}

	deleteStmt, err := db.Prepare(fmt.Sprintf(`	DELETE FROM %s.%s WHERE id=?`, databaseName, tableName))
	if err != nil {
		return nil, err
	}

	s := &MariadbStore{
		db:            db,
		databaseName:  databaseName,
		tableName:     tableName,
		insertStmt:    insertStmt,
		updateStmt:    updateStmt,
		selectStmt:    selectStmt,
		selectAllStmt: selectAllStmt,
		deleteStmt:    deleteStmt,
		Codecs:        securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
		stopChan:         make(chan struct{}),
		doneStoppingChan: make(chan struct{}),
	}

	s.cleanExpiredSessions()
	go s.loop()

	return s, nil
}

func (s *MariadbStore) Close() {
	s.stopChan <- struct{}{}
	<-s.doneStoppingChan

	s.insertStmt.Close()
	s.updateStmt.Close()
	s.selectStmt.Close()
	s.deleteStmt.Close()
}

func (s *MariadbStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

func (s *MariadbStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		if err == nil {
			err = s.load(session)
			if err == nil {
				session.IsNew = false
			}
		}
	}

	// if the client has a session cookie but the session doesn't exist then create a
	// new session for the client
	if err != nil {
		err = s.insert(session)
	}

	return session, err
}

func (s *MariadbStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Delete if max-age is <= 0
	if session.Options.MaxAge <= 0 {
		if err := s.erase(session.ID); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if session.ID == "" {
		if err := s.insert(session); err != nil {
			return err
		}
	} else {
		if err := s.save(session); err != nil {
			return err
		}
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

func (s *MariadbStore) MaxAge(age int) {
	s.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

func (s *MariadbStore) MaxLength(l int) {
	for _, c := range s.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

func (s *MariadbStore) loop() {
	t := time.NewTicker(time.Hour * 24)

	for {
		select {
		case <-t.C:
			s.cleanExpiredSessions()
		case <-s.stopChan:
			s.doneStoppingChan <- struct{}{}
			return
		}
	}
}

func (s *MariadbStore) cleanExpiredSessions() error {
	now := time.Now().Unix()

	rows, err := s.selectAllStmt.Query()
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var expires int64
		err := rows.Scan(&id, &expires)
		if err != nil {
			return err
		}

		if now > expires {
			if err := s.erase(id); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func (s *MariadbStore) insert(session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.Codecs...)
	if err != nil {
		return err
	}

	expires := time.Now().Add(time.Second * time.Duration(session.Options.MaxAge)).Unix()

	res, err := s.insertStmt.Exec(expires, encoded)
	if err != nil {
		return err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return err
	}

	session.ID = fmt.Sprintf("%d", id)

	return nil
}

func (s *MariadbStore) save(session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.Codecs...)
	if err != nil {
		return err
	}

	expires := time.Now().Add(time.Second * time.Duration(session.Options.MaxAge)).Unix()

	_, err = s.updateStmt.Exec(expires, encoded)
	return err
}

func (s *MariadbStore) load(session *sessions.Session) error {
	var sessionData string
	if err := s.selectStmt.QueryRow(session.ID).Scan(&sessionData); err != nil {
		return err
	}

	if err := securecookie.DecodeMulti(session.Name(), string(sessionData), &session.Values, s.Codecs...); err != nil {
		return err
	}

	return nil
}

func (s *MariadbStore) erase(id string) error {
	_, err := s.deleteStmt.Exec(id)
	return err
}
