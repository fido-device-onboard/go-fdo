// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package sqlite implements server-side persistence with a SQLite database.
package sqlite

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"
	_ "github.com/ncruces/go-sqlite3/embed" // Load sqlite WASM binary
	"golang.org/x/exp/maps"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
)

// DB implements FDO server state persistence.
type DB struct {
	AutoExtend               bool
	AutoRegisterRV           *fdo.To1d
	PreserveReplacedVouchers bool

	conn *sqlite3.Conn
}

// New creates or opens a SQLite database file using a single non-pooled
// connection.
func New(filename string) (*DB, error) {
	// Open a new or existing DB
	conn, err := sqlite3.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening sqlite DB: %w", err)
	}

	// Ensure required pragma are set
	pragma := []string{
		`PRAGMA foreign_keys = ON`,
	}
	for _, sql := range pragma {
		if err := conn.Exec(sql); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("error setting pragma: %w", err)
		}
	}

	// Ensure tables are created
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS secrets
			( type TEXT NOT NULL
			, secret BLOB NOT NULL
			)`,
		`CREATE TABLE IF NOT EXISTS mfg_keys
			( type INTEGER UNIQUE NOT NULL
			, pkcs8 BLOB NOT NULL
			, x509_chain BLOB NOT NULL
			)`,
		`CREATE TABLE IF NOT EXISTS owner_keys
			( type INTEGER UNIQUE NOT NULL
			, pkcs8 BLOB NOT NULL
			, x509_chain BLOB
			)`,
		`CREATE TABLE IF NOT EXISTS rv_blobs
			( guid BLOB PRIMARY KEY
			, rv BLOB NOT NULL
			)`,
		`CREATE TABLE IF NOT EXISTS sessions
			( id BLOB PRIMARY KEY
			, protocol INTEGER NOT NULL
			)`,
		`CREATE TABLE IF NOT EXISTS device_info
			( session BLOB
			, key_type INTEGER
			, key_encoding INTEGER
			, serial_number TEXT
			, info_string TEXT
			, csr BLOB
			, x509_chain BLOB NOT NULL
			, FOREIGN KEY(session) REFERENCES sessions(id) ON DELETE SET NULL
			)`,
		`CREATE TABLE IF NOT EXISTS incomplete_vouchers
			( session BLOB UNIQUE NOT NULL
			, header BLOB NOT NULL
			, FOREIGN KEY(session) REFERENCES sessions(id) ON DELETE CASCADE
			)`,
		`CREATE TABLE IF NOT EXISTS to1_sessions
			( session BLOB UNIQUE NOT NULL
			, nonce BLOB
			, alg INTEGER
			, FOREIGN KEY(session) REFERENCES sessions(id) ON DELETE CASCADE
			)`,
		`CREATE TABLE IF NOT EXISTS to2_sessions
			( session BLOB UNIQUE NOT NULL
			, guid BLOB
			, prove_device BLOB
			, setup_device BLOB
			, mtu INTEGER
			, FOREIGN KEY(session) REFERENCES sessions(id) ON DELETE CASCADE
			)`,
		`CREATE TABLE IF NOT EXISTS vouchers
			( guid BLOB PRIMARY KEY
			, cbor BLOB NOT NULL
			)`,
		`CREATE TABLE IF NOT EXISTS replacement_vouchers
			( session BLOB UNIQUE NOT NULL
			, guid BLOB
			, hmac BLOB
			, FOREIGN KEY(session) REFERENCES sessions(id) ON DELETE CASCADE
			)`,
		`CREATE TABLE IF NOT EXISTS key_exchanges
			( session BLOB UNIQUE NOT NULL
			, suite TEXT NOT NULL
			, cbor BLOB NOT NULL
			, FOREIGN KEY(session) REFERENCES sessions(id) ON DELETE CASCADE
			)`,
	}
	for _, sql := range stmts {
		if err := conn.Exec(sql); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("error creating tables: %w", err)
		}
	}

	return &DB{conn: conn}, nil
}

// Close closes the database connection.
//
// If the database connection is associated with unfinalized prepared
// statements, open blob handles, and/or unfinished backup objects, Close will
// leave the database connection open and return [sqlite3.BUSY].
func (db *DB) Close() error { return db.conn.Close() }

// Compile-time check for interface implementation correctness
var _ interface {
	fdo.TokenService
	fdo.DISessionState
	fdo.TO1SessionState
	fdo.TO2SessionState
	fdo.RendezvousBlobPersistentState
	fdo.VoucherPersistentState
	fdo.OwnerKeyPersistentState
} = (*DB)(nil)

const sessionIDSize = 16

// NewToken initializes state for a given protocol and return the
// associated token.
func (db *DB) NewToken(ctx context.Context, protocol fdo.Protocol) (string, error) {
	// Acquire HMAC secret
	secret, err := db.loadOrStoreSecret()
	if err != nil {
		return "", fmt.Errorf("error loading or storing HMAC secret: %w", err)
	}

	// Generate new session ID
	id := make([]byte, sessionIDSize)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}

	// Store session ID
	if err := db.insert("sessions", map[string]any{
		"id":       id,
		"protocol": int(protocol),
	}, nil); err != nil {
		return "", fmt.Errorf("error storing new session: %w", err)
	}

	// MAC and encode
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(id)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(id)), nil
}

func (db *DB) loadOrStoreSecret() ([]byte, error) {
	tx := db.conn.Begin()
	defer func() { _ = tx.Rollback() }()

	var readSecret []byte
	if err := db.query("secrets", []string{"secret"}, map[string]any{"type": "hmac"}, &readSecret); err != nil && !errors.Is(err, fdo.ErrNotFound) {
		return nil, fmt.Errorf("error reading hmac secret: %w", err)
	}
	if len(readSecret) > 0 {
		return readSecret, nil
	}

	// Insert new secret
	var secret [64]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, err
	}
	if err := db.insertWithinTx("secrets", map[string]any{"type": "hmac", "secret": secret[:]}, nil); err != nil {
		return nil, fmt.Errorf("error writing hmac secret: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return secret[:], nil
}

type contextKey struct{}

var tokenKey contextKey

// TokenContext injects a context with a token value so that it may be used
// for any of the XXXState interfaces.
func (db *DB) TokenContext(parent context.Context, token string) context.Context {
	return context.WithValue(parent, tokenKey, token)
}

// TokenFromContext gets the token value from a context. This is useful,
// because some TokenServices may allow token mutation, such as in the case
// of token-encoded state (i.e. JWTs/CWTs).
func (db *DB) TokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(tokenKey).(string)
	return token, ok
}

// InvalidateToken destroys the state associated with a given token.
func (db *DB) InvalidateToken(ctx context.Context) error {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.ErrNotFound
	}

	stmt, _, err := db.conn.Prepare(`DELETE FROM sessions WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("error preparing delete statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	if err := stmt.BindBlob(1, sessID); err != nil {
		return fmt.Errorf("error binding delete statement parameter: %w", err)
	}
	return stmt.Exec()
}

func (db *DB) sessionID(ctx context.Context) ([]byte, bool) {
	// Get HMAC secret
	secret, err := db.loadOrStoreSecret()
	if err != nil {
		return nil, false
	}

	// Decode token
	token, ok := ctx.Value(tokenKey).(string)
	if !ok {
		return nil, false
	}
	rawToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, false
	}
	id, mac1 := rawToken[:sessionIDSize], rawToken[sessionIDSize:]

	// Check HMAC
	hash := hmac.New(sha256.New, secret)
	_, _ = hash.Write(id)
	mac2 := make([]byte, hash.Size())
	hash.Sum(mac2[:0])
	if !hmac.Equal(mac1, mac2) {
		return nil, false
	}

	return id, true
}

func (db *DB) insert(table string, kvs, upsertWhere map[string]any) error {
	tx := db.conn.Begin()
	defer func() { _ = tx.Rollback() }()

	if err := db.insertWithinTx(table, kvs, upsertWhere); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) insertOrIgnore(table string, kvs map[string]any) error {
	return db.insertWithinTx(table, kvs, map[string]any{})
}

func (db *DB) insertWithinTx(table string, kvs, upsertWhere map[string]any) error {
	var orIgnore string
	if upsertWhere != nil {
		orIgnore = "OR IGNORE "
	}

	columns := maps.Keys(kvs)
	sql := fmt.Sprintf(
		"INSERT %sINTO %s (%s) VALUES (%s)",
		orIgnore,
		table,
		strings.Join(columns, ", "),
		":"+strings.Join(columns, ", :"),
	)
	insert, _, err := db.conn.Prepare(sql)
	if err != nil {
		return fmt.Errorf("error preparing insert: %w", err)
	}
	defer func() { _ = insert.Close() }()

	for key, val := range kvs {
		var err error
		switch value := val.(type) {
		case int:
			err = insert.BindInt(insert.BindIndex(":"+key), value)
		case string:
			err = insert.BindText(insert.BindIndex(":"+key), value)
		case []byte:
			err = insert.BindBlob(insert.BindIndex(":"+key), value)
		default:
			panic(fmt.Sprintf("programming error - unsupported type to bind %q to statement: %T", key, val))
		}
		if err != nil {
			return fmt.Errorf("error binding %q: %w", key, err)
		}
	}

	if err := insert.Exec(); err != nil {
		return err
	}

	if len(upsertWhere) > 0 {
		return db.update(table, kvs, upsertWhere)
	}
	return nil
}

func (db *DB) update(table string, kvs, where map[string]any) error {
	var vals []string
	for key := range kvs {
		vals = append(vals, key+" = :set_"+key)
	}
	var clauses []string
	for key := range where {
		clauses = append(clauses, key+" = :where_"+key)
	}
	sql := fmt.Sprintf(
		`UPDATE %s SET %s WHERE %s`,
		table,
		strings.Join(vals, ", "),
		strings.Join(clauses, " AND "),
	)
	update, _, err := db.conn.Prepare(sql)
	if err != nil {
		return fmt.Errorf("error preparing update: %w", err)
	}
	defer func() { _ = update.Close() }()

	for prefix, m := range map[string]map[string]any{
		"set_":   kvs,
		"where_": where,
	} {
		for key, val := range m {
			var err error
			switch value := val.(type) {
			case int:
				err = update.BindInt(update.BindIndex(":"+prefix+key), value)
			case string:
				err = update.BindText(update.BindIndex(":"+prefix+key), value)
			case []byte:
				err = update.BindBlob(update.BindIndex(":"+prefix+key), value)
			default:
				panic(fmt.Sprintf("programming error - unsupported type to bind %q to statement: %T", key, val))
			}
			if err != nil {
				return fmt.Errorf("error binding %q: %w", key, err)
			}
		}
	}

	return update.Exec()
}

//nolint:gocyclo
func (db *DB) query(table string, columns []string, where map[string]any, into ...any) error {
	if len(columns) != len(into) {
		panic("programming error - query must have the same number of columns and values")
	}

	var clauses []string
	for key := range where {
		clauses = append(clauses, key+" = :"+key)
	}
	sql := fmt.Sprintf(
		`SELECT %s FROM %s WHERE %s`,
		strings.Join(columns, ", "),
		table,
		strings.Join(clauses, " AND "),
	)
	query, _, err := db.conn.Prepare(sql)
	if err != nil {
		return fmt.Errorf("error preparing query: %w", err)
	}
	defer func() { _ = query.Close() }()

	for key, val := range where {
		var err error
		switch value := val.(type) {
		case int:
			err = query.BindInt(query.BindIndex(":"+key), value)
		case string:
			err = query.BindText(query.BindIndex(":"+key), value)
		case []byte:
			err = query.BindBlob(query.BindIndex(":"+key), value)
		default:
			panic(fmt.Sprintf("programming error - unsupported type to bind %q to statement: %T", key, val))
		}
		if err != nil {
			return fmt.Errorf("error binding %q: %w", key, err)
		}
	}

	if !query.Step() {
		if err := query.Err(); err != nil {
			return fmt.Errorf("error querying DB: %w", err)
		}
		return fdo.ErrNotFound
	}

	for i := 0; i < len(into); i++ {
		if query.ColumnType(i) == sqlite3.NULL {
			return fdo.ErrNotFound
		}
	}

	for i := 0; i < len(into); i++ {
		switch val := into[i].(type) {
		case *int:
			*val = query.ColumnInt(i)
		case *string:
			*val = query.ColumnText(i)
		case *[]byte:
			*val = query.ColumnBlob(i, nil)
		default:
			panic(fmt.Sprintf("programming error - unsupported type to query %q into: %T", columns[i], into))
		}
	}
	return nil
}

// AddManufacturerKey for signing device certificate chains. Unlike
// [DB.AddOwnerKey], chain is always required.
func (db *DB) AddManufacturerKey(keyType fdo.KeyType, key crypto.PrivateKey, chain []*x509.Certificate) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return db.insertOrIgnore("mfg_keys", map[string]any{
		"type":       int(keyType),
		"pkcs8":      der,
		"x509_chain": derEncode(chain),
	})
}

func (db *DB) manufacturerKey(keyType fdo.KeyType) (crypto.PrivateKey, []*x509.Certificate, error) {
	var pkcs8, der []byte
	if err := db.query("mfg_keys", []string{"pkcs8", "x509_chain"}, map[string]any{
		"type": int(keyType),
	}, &pkcs8, &der); err != nil {
		return nil, nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing manufacturer key: %w", err)
	}
	chain, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing manufacturer certificate chain: %w", err)
	}
	return key, chain, nil
}

// NewDeviceCertChain creates a device certificate chain based on info
// provided in the (non-normative) DI.AppStart message and also stores it
// in session state.
func (db *DB) NewDeviceCertChain(ctx context.Context, info fdo.DeviceMfgInfo) ([]*x509.Certificate, error) {
	// Validate device info
	csr := x509.CertificateRequest(info.CertInfo)
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR: %w", err)
	}

	// Sign CSR
	key, chain, err := db.manufacturerKey(info.KeyType)
	if err != nil {
		var unsupportedErr fdo.ErrUnsupportedKeyType
		if errors.As(err, &unsupportedErr) {
			return nil, unsupportedErr
		}
		return nil, fmt.Errorf("error retrieving manufacturer key [type=%s]: %w", info.KeyType, err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("error generating certificate serial number: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Issuer:       chain[0].Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * 360 * 24 * time.Hour), // Matches Java impl
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, chain[0], csr.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("error signing CSR: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("error parsing signed device cert: %w", err)
	}
	chain = append([]*x509.Certificate{cert}, chain...)

	// Store device info and associate it with session
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return nil, fdo.ErrInvalidSession
	}
	if err := db.insert("device_info", map[string]any{
		"key_type":      int(info.KeyType),
		"key_encoding":  int(info.KeyEncoding),
		"serial_number": info.SerialNumber,
		"info_string":   info.DeviceInfo,
		"csr":           info.CertInfo.Raw,
		"x509_chain":    derEncode(chain),
		"session":       sessID,
	}, nil); err != nil {
		return nil, fmt.Errorf("error persisting device certificate chain: %w", err)
	}

	return chain, nil
}

func derEncode(certs []*x509.Certificate) (der []byte) {
	for _, cert := range certs {
		der = append(der, cert.Raw...)
	}
	return der
}

// DeviceCertChain gets a device certificate chain from the current
// session.
func (db *DB) DeviceCertChain(ctx context.Context) ([]*x509.Certificate, error) {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return nil, fdo.ErrInvalidSession
	}

	var der []byte
	if err := db.query("device_info", []string{"x509_chain"}, map[string]any{
		"session": sessID,
	}, &der); err != nil {
		return nil, err
	}
	return x509.ParseCertificates(der)
}

// SetIncompleteVoucherHeader stores an incomplete (missing HMAC) voucher
// header tied to a session.
func (db *DB) SetIncompleteVoucherHeader(ctx context.Context, ovh *fdo.VoucherHeader) error {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.ErrInvalidSession
	}

	ovhCBOR, err := cbor.Marshal(ovh)
	if err != nil {
		return fmt.Errorf("error marshaling ownership voucher header: %w", err)
	}

	return db.insert("incomplete_vouchers", map[string]any{
		"session": sessID,
		"header":  ovhCBOR,
	}, nil)
}

// IncompleteVoucherHeader gets an incomplete (missing HMAC) voucher header
// which has not yet been persisted.
func (db *DB) IncompleteVoucherHeader(ctx context.Context) (*fdo.VoucherHeader, error) {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return nil, fdo.ErrInvalidSession
	}

	var ovhCBOR []byte
	if err := db.query("incomplete_vouchers", []string{"header"}, map[string]any{
		"session": sessID,
	}, &ovhCBOR); err != nil {
		return nil, err
	}

	var ovh fdo.VoucherHeader
	if err := cbor.Unmarshal(ovhCBOR, &ovh); err != nil {
		return nil, fmt.Errorf("error unmarshaling ownership voucher header from DB: %w", err)
	}
	return &ovh, nil
}

// SetTO1ProofNonce sets the Nonce expected in TO1.ProveToRV.
func (db *DB) SetTO1ProofNonce(ctx context.Context, nonce fdo.Nonce) error {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.ErrInvalidSession
	}
	return db.insert("to1_sessions",
		map[string]any{
			"session": sessID,
			"nonce":   nonce[:],
		},
		map[string]any{
			"session": sessID,
		})
}

// TO1ProofNonce returns the Nonce expected in TO1.ProveToRV.
func (db *DB) TO1ProofNonce(ctx context.Context) (fdo.Nonce, error) {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.Nonce{}, fdo.ErrInvalidSession
	}

	var into []byte
	if err := db.query("to1_sessions", []string{"nonce"}, map[string]any{
		"session": sessID,
	}, &into); err != nil {
		return fdo.Nonce{}, err
	}

	var nonce fdo.Nonce
	_ = copy(nonce[:], into)
	return nonce, nil
}

// SetGUID associates a voucher GUID with a TO2 session.
func (db *DB) SetGUID(ctx context.Context, guid fdo.GUID) error {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.ErrInvalidSession
	}
	return db.insert("to2_sessions",
		map[string]any{
			"session": sessID,
			"guid":    guid[:],
		},
		map[string]any{
			"session": sessID,
		})
}

// GUID retrieves the GUID of the voucher associated with the session.
func (db *DB) GUID(ctx context.Context) (fdo.GUID, error) {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.GUID{}, fdo.ErrInvalidSession
	}

	var result []byte
	if err := db.query("to2_sessions", []string{"guid"}, map[string]any{
		"session": sessID,
	}, &result); err != nil {
		return fdo.GUID{}, err
	}

	if len(result) != len(fdo.GUID{}) {
		return fdo.GUID{}, fmt.Errorf("invalid sized GUID in DB")
	}

	var guid fdo.GUID
	_ = copy(guid[:], result)
	return guid, nil
}

// NewVoucher creates and stores a new voucher.
func (db *DB) NewVoucher(ctx context.Context, ov *fdo.Voucher) error {
	if db.AutoExtend {
		if err := db.autoExtend(ov); err != nil {
			return fmt.Errorf("auto extend: %w", err)
		}

		if db.AutoRegisterRV != nil {
			if err := db.autoRegisterRV(ctx, ov); err != nil {
				return fmt.Errorf("auto register RV blob: %w", err)
			}
		}
	}

	data, err := cbor.Marshal(ov)
	if err != nil {
		return fmt.Errorf("error marshaling ownership voucher: %w", err)
	}
	return db.insert("vouchers", map[string]any{
		"guid": ov.Header.Val.GUID[:],
		"cbor": data,
	}, nil)
}

func (db *DB) autoExtend(ov *fdo.Voucher) error {
	keyType := ov.Header.Val.ManufacturerKey.Type
	owner, _, err := db.manufacturerKey(keyType)
	if err != nil {
		return fmt.Errorf("error getting %s manufacturer key: %w", keyType, err)
	}
	nextOwner, _, err := db.ownerKey(keyType)
	if err != nil {
		return fmt.Errorf("error getting %s owner key: %w", keyType, err)
	}
	switch owner := owner.(type) {
	case *ecdsa.PrivateKey:
		nextOwner, ok := nextOwner.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("owner key must be %s", keyType)
		}
		extended, err := fdo.ExtendVoucher(ov, owner, &nextOwner.PublicKey, nil)
		if err != nil {
			return err
		}
		*ov = *extended
	case *rsa.PrivateKey:
		nextOwner, ok := nextOwner.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("owner key must be %s", keyType)
		}
		extended, err := fdo.ExtendVoucher(ov, owner, &nextOwner.PublicKey, nil)
		if err != nil {
			return err
		}
		*ov = *extended
	default:
		return fmt.Errorf("invalid key type %T", owner)
	}

	return nil
}

func (db *DB) autoRegisterRV(ctx context.Context, ov *fdo.Voucher) error {
	keyType := ov.Header.Val.ManufacturerKey.Type
	nextOwner, _, err := db.ownerKey(keyType)
	if err != nil {
		return fmt.Errorf("error getting %s owner key: %w", keyType, err)
	}

	var opts crypto.SignerOpts
	switch keyType {
	case fdo.Rsa2048RestrKeyType, fdo.RsaPkcsKeyType, fdo.RsaPssKeyType:
		switch rsaPub := nextOwner.Public().(*rsa.PublicKey); rsaPub.Size() {
		case 2048 / 8:
			opts = crypto.SHA256
		case 3072 / 8:
			opts = crypto.SHA384
		default:
			return fmt.Errorf("unsupported RSA key size: %d bits", rsaPub.Size()*8)
		}

		if keyType == fdo.RsaPssKeyType {
			opts = &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       opts.(crypto.Hash),
			}
		}
	}

	sign1 := cose.Sign1[fdo.To1d, []byte]{
		Payload: cbor.NewByteWrap(*db.AutoRegisterRV),
	}
	if err := sign1.Sign(nextOwner, nil, nil, opts); err != nil {
		return fmt.Errorf("error signing to1d: %w", err)
	}
	if err := db.SetRVBlob(ctx, ov.Header.Val.GUID, &sign1); err != nil {
		return fmt.Errorf("error storing to1d: %w", err)
	}

	return nil
}

// ReplaceVoucher stores a new voucher, possibly deleting or marking the
// previous voucher as replaced.
func (db *DB) ReplaceVoucher(ctx context.Context, guid fdo.GUID, ov *fdo.Voucher) error {
	data, err := cbor.Marshal(ov)
	if err != nil {
		return fmt.Errorf("error marshaling ownership voucher: %w", err)
	}
	if db.PreserveReplacedVouchers {
		return db.insert("vouchers",
			map[string]any{
				"guid": ov.Header.Val.GUID[:],
				"cbor": data,
			}, nil)
	}
	return db.update("vouchers",
		map[string]any{
			"guid": ov.Header.Val.GUID[:],
			"cbor": data,
		},
		map[string]any{
			"guid": guid[:],
		},
	)
}

// Voucher retrieves a voucher by GUID.
func (db *DB) Voucher(ctx context.Context, guid fdo.GUID) (*fdo.Voucher, error) {
	var data []byte
	if err := db.query("vouchers", []string{"cbor"},
		map[string]any{"guid": guid[:]},
		&data,
	); err != nil {
		return nil, err
	}

	var ov fdo.Voucher
	if err := cbor.Unmarshal(data, &ov); err != nil {
		return nil, fmt.Errorf("error unmarshaling ownership voucher: %w", err)
	}
	return &ov, nil
}

// SetReplacementGUID stores the device GUID to persist at the end of TO2.
func (db *DB) SetReplacementGUID(ctx context.Context, guid fdo.GUID) error {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.ErrInvalidSession
	}
	return db.insert("replacement_vouchers",
		map[string]any{
			"session": sessID,
			"guid":    guid[:],
		},
		map[string]any{
			"session": sessID,
		},
	)
}

// ReplacementGUID retrieves the device GUID to persist at the end of TO2.
func (db *DB) ReplacementGUID(ctx context.Context) (fdo.GUID, error) {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.GUID{}, fdo.ErrInvalidSession
	}

	var into []byte
	if err := db.query("replacement_vouchers", []string{"guid"},
		map[string]any{"session": sessID}, &into,
	); err != nil {
		return fdo.GUID{}, err
	}
	if len(into) != len(fdo.GUID{}) {
		return fdo.GUID{}, fmt.Errorf("invalid sized GUID in DB")
	}

	var guid fdo.GUID
	_ = copy(guid[:], into)
	return guid, nil
}

// SetReplacementHmac stores the voucher HMAC to persist at the end of TO2.
func (db *DB) SetReplacementHmac(ctx context.Context, hmac fdo.Hmac) error {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.ErrInvalidSession
	}
	return db.insert("replacement_vouchers",
		map[string]any{
			"session": sessID,
			"hmac":    hmac.Value,
		},
		map[string]any{
			"session": sessID,
		},
	)
}

// ReplacementHmac retrieves the voucher HMAC to persist at the end of TO2.
func (db *DB) ReplacementHmac(ctx context.Context) (fdo.Hmac, error) {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.Hmac{}, fdo.ErrInvalidSession
	}

	var hmac []byte
	if err := db.query("replacement_vouchers", []string{"hmac"},
		map[string]any{"session": sessID}, &hmac,
	); err != nil {
		return fdo.Hmac{}, err
	}

	var alg fdo.HashAlg
	switch len(hmac) {
	case sha256.New().Size():
		alg = fdo.HmacSha256Hash
	case sha512.New384().Size():
		alg = fdo.HmacSha384Hash
	default:
		return fdo.Hmac{}, fmt.Errorf("invalid hmac length: %d", len(hmac))
	}

	return fdo.Hmac{
		Algorithm: alg,
		Value:     hmac,
	}, nil
}

// SetSession updates the current key exchange/encryption session based on
// an opaque "authorization" token.
func (db *DB) SetSession(ctx context.Context, suite kex.Suite, sess kex.Session) error {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.ErrInvalidSession
	}

	stateMarshaler, ok := sess.(encoding.BinaryMarshaler)
	if !ok {
		return fmt.Errorf("key exchange state does not support binary marshaling")
	}
	state, err := stateMarshaler.MarshalBinary()
	if err != nil {
		return fmt.Errorf("error marshaling key exchange key exchange state: %w", err)
	}

	return db.insert("key_exchanges",
		map[string]any{
			"session": sessID,
			"suite":   string(suite),
			"cbor":    state,
		},
		map[string]any{
			"session": sessID,
		},
	)
}

// Session returns the current key exchange/encryption session based on an
// opaque "authorization" token.
func (db *DB) Session(ctx context.Context, token string) (kex.Suite, kex.Session, error) {
	sessID, ok := db.sessionID(db.TokenContext(ctx, token))
	if !ok {
		return "", nil, fdo.ErrInvalidSession
	}

	var suite string
	var sessData []byte
	if err := db.query("key_exchanges", []string{"suite", "cbor"}, map[string]any{
		"session": sessID,
	}, &suite, &sessData); err != nil {
		return "", nil, fmt.Errorf("error querying key exchange session: %w", err)
	}

	sess := kex.Suite(suite).New(nil, 1)
	stateUnmarshaler, ok := sess.(encoding.BinaryUnmarshaler)
	if !ok {
		return "", nil, fmt.Errorf("key exchange state does not support binary unmarshaling")
	}
	if err := stateUnmarshaler.UnmarshalBinary(sessData); err != nil {
		return "", nil, fmt.Errorf("error unmarshaling key exchange key exchange state: %w", err)
	}

	return kex.Suite(suite), sess, nil
}

// SetProveDeviceNonce stores the Nonce used in TO2.ProveDevice for use in
// TO2.Done.
func (db *DB) SetProveDeviceNonce(ctx context.Context, nonce fdo.Nonce) error {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.ErrInvalidSession
	}
	return db.insert("to2_sessions",
		map[string]any{
			"session":      sessID,
			"prove_device": nonce[:],
		},
		map[string]any{
			"session": sessID,
		},
	)
}

// ProveDeviceNonce returns the Nonce used in TO2.ProveDevice and TO2.Done.
func (db *DB) ProveDeviceNonce(ctx context.Context) (fdo.Nonce, error) {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.Nonce{}, fdo.ErrInvalidSession
	}

	var into []byte
	if err := db.query("to2_sessions", []string{"prove_device"}, map[string]any{
		"session": sessID,
	}, &into); err != nil {
		return fdo.Nonce{}, err
	}
	if len(into) != len(fdo.Nonce{}) {
		return fdo.Nonce{}, fmt.Errorf("invalid sized nonce in DB")
	}

	var nonce fdo.Nonce
	_ = copy(nonce[:], into)
	return nonce, nil
}

// SetSetupDeviceNonce stores the Nonce used in TO2.SetupDevice for use in
// TO2.Done2.
func (db *DB) SetSetupDeviceNonce(ctx context.Context, nonce fdo.Nonce) error {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.ErrInvalidSession
	}
	return db.insert("to2_sessions",
		map[string]any{
			"session":      sessID,
			"setup_device": nonce[:],
		},
		map[string]any{
			"session": sessID,
		},
	)
}

// SetupDeviceNonce returns the Nonce used in TO2.SetupDevice and
// TO2.Done2.
func (db *DB) SetupDeviceNonce(ctx context.Context) (fdo.Nonce, error) {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.Nonce{}, fdo.ErrInvalidSession
	}

	var into []byte
	if err := db.query("to2_sessions", []string{"setup_device"}, map[string]any{
		"session": sessID,
	}, &into); err != nil {
		return fdo.Nonce{}, err
	}
	if len(into) != len(fdo.Nonce{}) {
		return fdo.Nonce{}, fmt.Errorf("invalid sized nonce in DB")
	}

	var nonce fdo.Nonce
	_ = copy(nonce[:], into)
	return nonce, nil
}

// AddOwnerKey to retrieve with [DB.Signer]. chain may be nil, in which
// case X509 public key encoding will be used instead of X5Chain.
func (db *DB) AddOwnerKey(keyType fdo.KeyType, key crypto.PrivateKey, chain []*x509.Certificate) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if chain == nil {
		return db.insertOrIgnore("owner_keys", map[string]any{
			"type":  int(keyType),
			"pkcs8": der,
		})
	}
	return db.insertOrIgnore("owner_keys", map[string]any{
		"type":       int(keyType),
		"pkcs8":      der,
		"x509_chain": derEncode(chain),
	})
}

func (db *DB) ownerKey(keyType fdo.KeyType) (crypto.Signer, []*x509.Certificate, error) {
	query, _, err := db.conn.Prepare(`SELECT pkcs8, x509_chain FROM owner_keys WHERE type = ?`)
	if err != nil {
		return nil, nil, fmt.Errorf("error preparing query: %w", err)
	}
	defer func() { _ = query.Close() }()
	if err := query.BindInt(1, int(keyType)); err != nil {
		return nil, nil, fmt.Errorf("error binding query parameter: %w", err)
	}
	if !query.Step() {
		if err := query.Err(); err != nil {
			return nil, nil, fmt.Errorf("error querying DB: %w", err)
		}
		return nil, nil, fdo.ErrNotFound
	}

	// TODO: Randomize result? Return multiple?

	key, err := x509.ParsePKCS8PrivateKey(query.ColumnBlob(0, nil))
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing owner key: %w", err)
	}
	chain, err := x509.ParseCertificates(query.ColumnBlob(1, nil))
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing owner certificate chain: %w", err)
	}
	return key.(crypto.Signer), chain, nil
}

// Signer returns the private key matching a given key type.
func (db *DB) Signer(keyType fdo.KeyType) (crypto.Signer, bool) {
	key, _, err := db.ownerKey(keyType)
	if err != nil {
		return nil, false
	}
	return key, true
}

// SetMTU sets the max service info size the device may receive.
func (db *DB) SetMTU(ctx context.Context, mtu uint16) error {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return fdo.ErrInvalidSession
	}
	return db.insert("to2_sessions",
		map[string]any{
			"session": sessID,
			"mtu":     int(mtu),
		},
		map[string]any{
			"session": sessID,
		})
}

// MTU returns the max service info size the device may receive.
func (db *DB) MTU(ctx context.Context) (uint16, error) {
	sessID, ok := db.sessionID(ctx)
	if !ok {
		return 0, fdo.ErrInvalidSession
	}

	var mtu int
	if err := db.query("to2_sessions", []string{"mtu"}, map[string]any{
		"session": sessID,
	}, &mtu); err != nil {
		return 0, err
	}

	return uint16(mtu), nil
}

// SetRVBlob sets the owner rendezvous blob for a device.
func (db *DB) SetRVBlob(ctx context.Context, guid fdo.GUID, to1d *cose.Sign1[fdo.To1d, []byte]) error {
	blob, err := cbor.Marshal(to1d)
	if err != nil {
		return fmt.Errorf("error marshaling rendezvous blob: %w", err)
	}
	return db.insert("rv_blobs",
		map[string]any{
			"guid": guid[:],
			"rv":   blob,
		},
		nil)
}

// RVBlob returns the owner rendezvous blob for a device.
func (db *DB) RVBlob(ctx context.Context, guid fdo.GUID) (*cose.Sign1[fdo.To1d, []byte], error) {
	var blob []byte
	if err := db.query("rv_blobs", []string{"rv"}, map[string]any{
		"guid": guid[:],
	}, &blob); err != nil {
		return nil, err
	}

	var to1d cose.Sign1[fdo.To1d, []byte]
	if err := cbor.Unmarshal(blob, &to1d); err != nil {
		return nil, fmt.Errorf("error unmarshaling rendezvous blob: %w", err)
	}
	return &to1d, nil
}
