package mariadbstore

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type MariadbStore struct {
	db        *sql.DB
	tableName string
	Codecs    []securecookie.Codec
	Options   *sessions.Options
}

func NewMariadbStore(db *sql.DB, tableName string, keyPairs ...[]byte) (*MariadbStore, error) {
	if db == nil {
		return nil, errors.New("db cannot be nil")
	}

	createTableQuery := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
			session_data LONGBLOB
		) ENGINE=InnoDB;
	`, tableName)

	if _, err := db.Exec(createTableQuery); err != nil {
		return nil, err
	}

	return &MariadbStore{
		db:        db,
		tableName: tableName,
		Codecs:    securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
	}, nil
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
	return session, err
}

func (s *MariadbStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Delete if max-age is <= 0
	if session.Options.MaxAge <= 0 {
		if err := s.erase(session); err != nil {
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

	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		s.Codecs...)
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

func (s *MariadbStore) insert(session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.Codecs...)
	if err != nil {
		return err
	}

	insertSessionQuery := fmt.Sprintf(`
		INSERT INTO %s SET session_data=?
	`, s.tableName)

	res, err := s.db.Exec(insertSessionQuery, encoded)
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

	updateSessionQuery := fmt.Sprintf(`
		UPDATE %s SET session_data=?
	`, s.tableName)

	_, err = s.db.Exec(updateSessionQuery, encoded)
	return err
}

func (s *MariadbStore) load(session *sessions.Session) error {
	getSessionQuery := fmt.Sprintf(`
		SELECT session_data FROM %s WHERE id=?
	`, s.tableName)

	var sessionData string
	if err := s.db.QueryRow(getSessionQuery, session.ID).Scan(&sessionData); err != nil {
		return err
	}

	if err := securecookie.DecodeMulti(session.Name(), string(sessionData), &session.Values, s.Codecs...); err != nil {
		return err
	}

	return nil
}

func (s *MariadbStore) erase(session *sessions.Session) error {
	deleteSessionQuery := fmt.Sprintf(`
		DELETE FROM  %s WHERE id=?
	`, s.tableName)

	_, err := s.db.Exec(deleteSessionQuery, session.ID)
	return err
}
