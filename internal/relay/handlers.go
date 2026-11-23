package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/envelope"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/frame"
)

const maxRosterBody = 2 << 20

type createReq struct {
	GroupID       string `json:"group_id"`
	Ed25519Pub    []byte `json:"ed25519_pub"`
	RosterBlob    []byte `json:"roster_blob"`
	RosterVersion uint64 `json:"roster_version"`
	Sig           []byte `json:"sig"`
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.lim.enroll.peek(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	if !tokenEqual(r.Header.Get("X-ECB-Enroll"), s.cfg.EnrollToken) {
		s.lim.enroll.take(ip)
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var req createReq
	if !readJSON(w, r, maxRosterBody, &req) {
		return
	}
	gid, ok := parseGID(req.GroupID)
	if !ok || len(req.Ed25519Pub) != ed25519.PublicKeySize || req.RosterVersion < 1 ||
		len(req.RosterBlob) == 0 || len(req.RosterBlob) > 1<<20 || len(req.Sig) != ed25519.SignatureSize {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	pub := ed25519.PublicKey(req.Ed25519Pub)
	if !ed25519.Verify(pub, GroupCreateMessage(gid, pub, req.RosterBlob, req.RosterVersion), req.Sig) {
		s.lim.enroll.take(ip)
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	switch err := s.groups.create(req.GroupID, pubKey(pub), req.RosterBlob, req.RosterVersion); {
	case errors.Is(err, errGroupExists):
		writeErr(w, http.StatusConflict, "group exists")
	case err != nil:
		s.log.Error("persist groups failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
	default:
		writeJSON(w, http.StatusCreated, map[string]string{"group_id": req.GroupID})
	}
}

type publishReq struct {
	Version uint64   `json:"version"`
	Blob    []byte   `json:"blob"`
	Keys    [][]byte `json:"keys"`
	Sig     []byte   `json:"sig"`
	Signer  []byte   `json:"signer"`
}

func (s *Server) publishRoster(w http.ResponseWriter, r *http.Request, sess *session) {
	gid := r.PathValue("gid")
	gidB, ok := parseGID(gid)
	if !ok || gid != sess.gid {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var req publishReq
	if !readJSON(w, r, maxRosterBody, &req) {
		return
	}
	if len(req.Signer) != ed25519.PublicKeySize || len(req.Sig) != ed25519.SignatureSize ||
		len(req.Blob) == 0 || len(req.Blob) > 1<<20 || len(req.Keys) == 0 || len(req.Keys) > maxGroupDevices {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	keys := make([]ed25519.PublicKey, 0, len(req.Keys))
	set := map[pubKey]struct{}{}
	for _, k := range req.Keys {
		if len(k) != ed25519.PublicKeySize {
			writeErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		if _, dup := set[pubKey(k)]; dup {
			writeErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		set[pubKey(k)] = struct{}{}
		keys = append(keys, ed25519.PublicKey(k))
	}
	if !ed25519.Verify(ed25519.PublicKey(req.Signer), RosterPubMessage(gidB, req.Version, req.Blob, keys), req.Sig) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	switch err := s.groups.publish(gid, pubKey(req.Signer), req.Version, req.Blob, mapKeys(set)); {
	case errors.Is(err, errNotMember):
		writeErr(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, errOldVersion):
		writeErr(w, http.StatusConflict, "version not newer")
	case err != nil:
		s.log.Error("persist groups failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
	default:
		// Removal takes effect now: drop tokens and close connections.
		s.auth.revoke(gid, set)
		s.hub.kick(gid, set)
		writeJSON(w, http.StatusOK, map[string]uint64{"version": req.Version})
	}
}

func mapKeys(m map[pubKey]struct{}) []pubKey {
	out := make([]pubKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (s *Server) getRoster(w http.ResponseWriter, r *http.Request, sess *session) {
	gid := r.PathValue("gid")
	if gid != sess.gid {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	ctrlDeadlines(w, 20*time.Second)
	blob, ver, ok := s.groups.roster(gid)
	if !ok {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": ver, "blob": blob})
}

// ---- auth ----------------------------------------------------------------

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	if !s.lim.authIP.allow(s.clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	var req struct {
		GroupID string `json:"group_id"`
	}
	if !readJSON(w, r, 1<<10, &req) {
		return
	}
	if _, ok := parseGID(req.GroupID); !ok {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	// A nonce is returned even for unknown groups: no existence oracle.
	n, ok := s.auth.newNonce(req.GroupID)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "busy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"nonce": n})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if !s.lim.authIP.allow(s.clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	var req struct {
		GroupID string `json:"group_id"`
		Pub     []byte `json:"pub"`
		Nonce   string `json:"nonce"`
		Sig     []byte `json:"sig"`
	}
	if !readJSON(w, r, 4<<10, &req) {
		return
	}
	deny := func() { writeErr(w, http.StatusUnauthorized, "unauthorized") }
	gid, ok := parseGID(req.GroupID)
	if !ok || len(req.Pub) != ed25519.PublicKeySize {
		deny()
		return
	}
	if !s.lim.authDev.allow(hex.EncodeToString(req.Pub)) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	nonceRaw, err := base64.StdEncoding.DecodeString(req.Nonce)
	valid := s.auth.consumeNonce(req.Nonce, req.GroupID) && err == nil && len(req.Sig) == ed25519.SignatureSize &&
		s.groups.has(req.GroupID, pubKey(req.Pub)) &&
		ed25519.Verify(ed25519.PublicKey(req.Pub), AuthMessage(nonceRaw, gid), req.Sig)
	if !valid {
		deny()
		return
	}
	tok, ok := s.auth.issue(req.GroupID, pubKey(req.Pub))
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "busy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "expires_in": int(tokenTTL / time.Second)})
}

// ---- items ---------------------------------------------------------------

var (
	errMismatch = errors.New("header does not match token")
	errBadTime  = errors.New("created_ms out of range")
)

// frameOverhead is header + signature; ct_len cap = max item bytes - overhead.
const frameOverhead = frame.HeaderSize + frame.SigSize

func (s *Server) postItem(w http.ResponseWriter, r *http.Request, sess *session) {
	devHex := hex.EncodeToString(sess.dev[:])
	if !s.lim.items.allow(devHex) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	cl := r.ContentLength
	switch {
	case cl < 0:
		writeErr(w, http.StatusLengthRequired, "content-length required")
		return
	case cl > s.cfg.MaxItemBytes:
		w.Header().Set("Connection", "close")
		writeErr(w, http.StatusRequestEntityTooLarge, "item too large")
		return
	case cl < frameOverhead:
		writeErr(w, http.StatusBadRequest, "invalid item")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(2*time.Minute + time.Duration(cl/(64<<10))*time.Second))
	body := &countReader{r: http.MaxBytesReader(w, r.Body, cl)}

	tmp, err := s.items.newTemp(sess.gid)
	if err != nil {
		s.log.Error("spool create failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	keys := s.groups.keyByDevice(sess.gid)
	gidB, _ := parseGID(sess.gid)
	v := &frame.Verifier{
		Lookup: func(id [16]byte) (ed25519.PublicKey, bool) {
			k, ok := keys[id]
			return k, ok
		},
		MaxCiphertext: uint64(max(s.cfg.MaxItemBytes-frameOverhead, 0)),
		CheckHeader: func(h frame.Header) error {
			if h.GroupID != gidB || h.SenderID != sess.dev {
				return errMismatch
			}
			created := time.UnixMilli(h.CreatedMs)
			now := s.now()
			if created.Before(now.Add(-s.cfg.ItemTTL-envelope.ClockSkew)) || created.After(now.Add(envelope.ClockSkew)) {
				return errBadTime
			}
			return nil
		},
	}
	// The verifier only forwards the ciphertext, so tee the whole frame
	// (header + ct + sig) into the spool file and discard the verifier copy.
	if _, err := v.Verify(io.TeeReader(body, tmp), io.Discard); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe), errors.Is(err, frame.ErrTooLarge):
			w.Header().Set("Connection", "close")
			writeErr(w, http.StatusRequestEntityTooLarge, "item too large")
		case errors.Is(err, errMismatch), errors.Is(err, frame.ErrUnknownSender):
			writeErr(w, http.StatusForbidden, "forbidden")
		default:
			writeErr(w, http.StatusBadRequest, "invalid item")
		}
		return
	}
	if body.n != cl {
		writeErr(w, http.StatusBadRequest, "invalid item")
		return
	}
	if err := tmp.Close(); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if s.afterVerify != nil {
		s.afterVerify()
	}
	var meta *itemMeta
	err = s.groups.whileMember(sess.gid, sess.pub, func() (e error) {
		meta, e = s.items.commit(sess.gid, tmp.Name(), devHex, body.n)
		return e
	})
	if err != nil {
		if errors.Is(err, errNotMember) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
		} else {
			writeErr(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	committed = true
	s.hub.publish(sess.gid, Event{T: "item", ID: meta.id, Size: meta.size, From: devHex})
	ctrlDeadlines(w, 20*time.Second)
	writeJSON(w, http.StatusOK, map[string]any{"id": meta.id, "size": meta.size})
}

// countReader counts the bytes actually read from the request body.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (s *Server) getItem(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	if !isHex(id, 32) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	f, m := s.items.open(sess.gid, id)
	if f == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	defer f.Close()
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2*time.Minute + time.Duration(m.size/(64<<10))*time.Second))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "", time.Time{}, f)
}

// ---- events --------------------------------------------------------------

func (s *Server) events(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query()
	wait := 0
	if v := q.Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		wait = min(n, 25)
	}
	ctx, done := s.connCtx(r, sess)
	defer done()
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(wait)*time.Second + 20*time.Second))
	wake, unsub := s.hub.subscribe(sess.gid)
	defer unsub()
	var after uint64
	if v := q.Get("after"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		after = n
	} else {
		after = s.hub.cur(sess.gid)
	}
	self := hex.EncodeToString(sess.dev[:])
	timer := time.NewTimer(time.Duration(wait) * time.Second)
	defer timer.Stop()
	for {
		evs, cur := s.hub.since(sess.gid, after, self)
		if len(evs) > 0 || wait == 0 {
			if evs == nil {
				evs = []Event{}
			}
			writeJSON(w, http.StatusOK, map[string]any{"events": evs, "seq": cur})
			return
		}
		after = cur
		select {
		case <-wake:
		case <-timer.C:
			writeJSON(w, http.StatusOK, map[string]any{"events": []Event{}, "seq": cur})
			return
		case <-ctx.Done():
			if errors.Is(context.Cause(ctx), errRevoked) {
				writeErr(w, http.StatusUnauthorized, "unauthorized")
			}
			return
		}
	}
}

func (s *Server) ws(w http.ResponseWriter, r *http.Request, sess *session) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return // Accept already replied
	}
	c.SetReadLimit(1024)
	ctx, done := s.connCtx(r, sess)
	defer done()
	cctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	self := hex.EncodeToString(sess.dev[:])
	wake, unsub := s.hub.subscribe(sess.gid)
	defer unsub()
	last := s.hub.cur(sess.gid)
	if v := r.URL.Query().Get("after"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			last = n
		}
	}

	// Hello tells the client where the stream starts so a later reconnect can
	// resume with ?after= even if no item has arrived yet.
	hello, _ := json.Marshal(map[string]any{"t": "hello", "seq": last})
	if err := c.Write(cctx, websocket.MessageText, hello); err != nil {
		_ = c.Close(websocket.StatusInternalError, "")
		return
	}

	// The reader must NOT use cctx: cancelling a Read context makes the
	// library drop the TCP connection, which would pre-empt the close frame
	// (status "revoked") we want the client to see.
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			typ, data, err := c.Read(rctx)
			if err != nil {
				cancel(err)
				return
			}
			if typ == websocket.MessageText && string(data) == `{"t":"ping"}` {
				wctx, wc := context.WithTimeout(cctx, 10*time.Second)
				err := c.Write(wctx, websocket.MessageText, []byte(`{"t":"pong"}`))
				wc()
				if err != nil {
					cancel(err)
					return
				}
			}
		}
	}()

	ping := time.NewTicker(s.cfg.PingInterval)
	defer ping.Stop()
loop:
	for {
		evs, cur := s.hub.since(sess.gid, last, self)
		for _, e := range evs {
			b, _ := json.Marshal(e)
			wctx, wc := context.WithTimeout(cctx, 10*time.Second)
			err := c.Write(wctx, websocket.MessageText, b)
			wc()
			if err != nil {
				cancel(err)
				break loop
			}
		}
		last = cur
		select {
		case <-wake:
		case <-ping.C:
			pctx, pc := context.WithTimeout(cctx, 10*time.Second)
			err := c.Ping(pctx)
			pc()
			if err != nil {
				cancel(err)
				break loop
			}
		case <-cctx.Done():
			break loop
		}
	}
	if errors.Is(context.Cause(cctx), errRevoked) {
		_ = c.Close(websocket.StatusPolicyViolation, "revoked")
	} else {
		_ = c.Close(websocket.StatusNormalClosure, "")
	}
	rcancel()
	<-readerDone
}

// ---- pairing mailbox -----------------------------------------------------

func (s *Server) pairCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	id, e := s.pairs.create(sess.gid)
	switch e {
	case pairOK:
		writeJSON(w, http.StatusOK, map[string]any{"mailbox": id, "expires_in": int(pairTTL / time.Second)})
	case pairTooMany:
		writeErr(w, http.StatusTooManyRequests, "too many active mailboxes")
	default:
		writeErr(w, http.StatusServiceUnavailable, "busy")
	}
}

// pairID parses the mailbox path value and applies the per-IP limit.
func (s *Server) pairID(w http.ResponseWriter, r *http.Request) (int, bool) {
	if !s.lim.pair.allow(s.clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return 0, false
	}
	id, err := strconv.Atoi(r.PathValue("mailbox"))
	if err != nil || id < 1 || id > pairMaxID {
		writeErr(w, http.StatusNotFound, "not found")
		return 0, false
	}
	return id, true
}

func (s *Server) pairPost(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pairID(w, r)
	if !ok {
		return
	}
	var req struct {
		To   string `json:"to"`
		Data []byte `json:"data"`
	}
	if !readJSON(w, r, 24<<10, &req) {
		return
	}
	if (req.To != "a" && req.To != "b") || len(req.Data) == 0 || len(req.Data) > pairMaxData {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	switch s.pairs.post(id, req.To, req.Data) {
	case pairOK:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case pairFull:
		if !s.lim.pairBurn.allow(s.clientIP(r)) {
			writeErr(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		s.pairs.burn(id)
		writeErr(w, http.StatusTooManyRequests, "mailbox full")
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) pairGet(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pairID(w, r)
	if !ok {
		return
	}
	party := r.URL.Query().Get("for")
	if party != "a" && party != "b" {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	wait := 0
	if v := r.URL.Query().Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		wait = min(n, 25)
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(wait)*time.Second + 20*time.Second))
	ctx, stop := context.WithCancel(r.Context())
	defer stop()
	defer context.AfterFunc(s.ctx, stop)()
	data, gone := s.pairs.get(ctx, id, party, time.Duration(wait)*time.Second)
	switch {
	case gone:
		writeErr(w, http.StatusNotFound, "not found")
	case data == nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, map[string][]byte{"data": data})
	}
}

func (s *Server) pairBurn(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pairID(w, r)
	if !ok {
		return
	}
	if !s.lim.pairBurn.allow(s.clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	s.pairs.burn(id)
	w.WriteHeader(http.StatusNoContent)
}
