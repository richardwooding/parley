package service

import (
	"fmt"
	"maps"
	"strings"
	"unicode"

	"github.com/richardwooding/parley/session"
	"github.com/richardwooding/parley/wire"
)

// CtlID is the reserved control service, present in every session. The host
// broadcasts the roster (roles live inside the encrypted channel — the relay
// never learns them) and answers snapshot requests so late joiners catch up.
const CtlID = "ctl"

const (
	ctlKindAnnounce    uint8 = 1
	ctlKindSnapshotReq uint8 = 2
	ctlKindSnapshot    uint8 = 3
	ctlKindIdentity    uint8 = 4 // participant → host: my screen name
)

// maxNameLen caps a screen name (runes). Names are self-asserted display
// labels, distributed inside the encrypted ctl channel — the relay never
// sees them.
const maxNameLen = 24

type ctlMsg struct {
	Kind      uint8             `cbor:"1,keyasint"`
	Roster    map[uint32]uint8  `cbor:"2,keyasint,omitempty"`
	Services  []ServiceInfo     `cbor:"3,keyasint,omitempty"`
	Snapshots map[string][]byte `cbor:"4,keyasint,omitempty"`
	Name      string            `cbor:"5,keyasint,omitempty"` // identity: sender's name
	Names     map[uint32]string `cbor:"6,keyasint,omitempty"` // announce: id → name
	Endpoint  string            `cbor:"7,keyasint,omitempty"` // identity: sender's opaque per-member attribute
	Endpoints map[uint32]string `cbor:"8,keyasint,omitempty"` // announce: id → push endpoint
	PushKey   string            `cbor:"9,keyasint,omitempty"` // announce: opaque per-session attribute (host-set)
}

// ServiceInfo names one service a session end is running.
type ServiceInfo struct {
	ID      string `cbor:"1,keyasint"`
	Version int    `cbor:"2,keyasint"`
}

// Roster is the ctl service's event: current membership with roles and
// screen names, plus what services the host runs. Endpoints and PushKey carry
// opaque attribute plumbing: one string per member and one per session
// (kibitz uses these for Web Push endpoints and the session VAPID keypair —
// blobs the Go layer only
// relays). All of it rides inside the encrypted channel — the relay never sees
// it.
type Roster struct {
	Members   map[wire.ParticipantID]session.Role
	Names     map[wire.ParticipantID]string
	Endpoints map[wire.ParticipantID]string
	PushKey   string
	Services  []ServiceInfo
}

type ctlService struct {
	mux *Mux
	Base
	// roster + names + endpoints are host-authoritative; joiners hold the last
	// announced copy. Names/endpoints are self-asserted (each reports its own).
	roster       map[wire.ParticipantID]session.Role
	names        map[wire.ParticipantID]string
	endpoints    map[wire.ParticipantID]string
	pushKey      string // per-session attribute (host-set; opaque blob)
	selfName     string
	selfEndpoint string
}

func newCtl(m *Mux) *ctlService {
	return &ctlService{
		mux:       m,
		roster:    map[wire.ParticipantID]session.Role{},
		names:     map[wire.ParticipantID]string{},
		endpoints: map[wire.ParticipantID]string{},
	}
}

// sanitizeName trims, strips control characters, and caps the length.
func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len([]rune(s)) > maxNameLen {
		s = string([]rune(s)[:maxNameLen])
	}
	return s
}

// setName sets the local participant's screen name and distributes it: the
// host records it and re-announces the roster; a joiner reports it to the
// host, which folds it into the authoritative roster.
func (c *ctlService) setName(name string) {
	name = sanitizeName(name)
	if name == "" {
		return
	}
	c.selfName = name
	c.names[c.Ctx().Self] = name
	if c.Ctx().Host {
		c.announce()
		return
	}
	if body, err := wire.Marshal(ctlMsg{Kind: ctlKindIdentity, Name: name}); err == nil {
		_ = c.Ctx().Send.SendTo(c.Ctx().HostID, CtlID, body)
	}
}

// setEndpoint records the local participant's attribute string and distributes
// it like a name: the host folds it into the authoritative roster and
// re-announces; a joiner reports it to the host. Peers use it to send this
// participant a "your turn" push.
func (c *ctlService) setEndpoint(endpoint string) {
	c.selfEndpoint = endpoint
	c.endpoints[c.Ctx().Self] = endpoint
	if c.Ctx().Host {
		c.announce()
		return
	}
	if body, err := wire.Marshal(ctlMsg{Kind: ctlKindIdentity, Endpoint: endpoint}); err == nil {
		_ = c.Ctx().Send.SendTo(c.Ctx().HostID, CtlID, body)
	}
}

// setPushKey (host only) records the per-session attribute blob the host
// generated and re-announces so every member gets it. It's an opaque browser
// blob to the Go layer.
func (c *ctlService) setPushKey(key string) {
	if !c.Ctx().Host {
		return
	}
	c.pushKey = key
	c.announce()
}

func (c *ctlService) ID() string   { return CtlID }
func (c *ctlService) Version() int { return 1 }

func (c *ctlService) Attach(ctx Context) {
	c.SetContext(ctx)
	if ctx.Host {
		c.roster[ctx.Self] = session.RoleHost
	}
}

func (c *ctlService) HandleFrame(from wire.ParticipantID, body []byte) error {
	msg, err := wire.Body[ctlMsg](body)
	if err != nil {
		return fmt.Errorf("ctl: %w", err)
	}
	switch msg.Kind {
	case ctlKindAnnounce:
		return c.handleAnnounce(from, msg)
	case ctlKindIdentity:
		return c.handleIdentity(from, msg)
	case ctlKindSnapshotReq:
		return c.handleSnapshotReq(from)
	case ctlKindSnapshot:
		return c.handleSnapshot(from, msg)
	}
	return nil
}

// handleAnnounce adopts a host-authoritative roster (roster/names/endpoints/
// pushKey) and emits the resulting Roster event. Host-only sender.
func (c *ctlService) handleAnnounce(from wire.ParticipantID, msg ctlMsg) error {
	if from != c.Ctx().HostID {
		return fmt.Errorf("ctl: announce from non-host %d", from)
	}
	c.roster = map[wire.ParticipantID]session.Role{}
	for id, r := range msg.Roster {
		c.roster[wire.ParticipantID(id)] = session.Role(r)
	}
	c.names = map[wire.ParticipantID]string{}
	for id, n := range msg.Names {
		c.names[wire.ParticipantID(id)] = n
	}
	c.endpoints = map[wire.ParticipantID]string{}
	for id, ep := range msg.Endpoints {
		c.endpoints[wire.ParticipantID(id)] = ep
	}
	c.pushKey = msg.PushKey
	c.mux.emit(c.roster3(msg.Services))
	return nil
}

// handleIdentity folds a participant's self-asserted name/endpoint into the
// authoritative roster and re-announces. Only the host aggregates; a
// participant reports its own.
func (c *ctlService) handleIdentity(from wire.ParticipantID, msg ctlMsg) error {
	if !c.Ctx().Host {
		return nil
	}
	if msg.Name != "" {
		c.names[from] = sanitizeName(msg.Name)
	}
	if msg.Endpoint != "" {
		c.endpoints[from] = msg.Endpoint
	}
	c.announce()
	return nil
}

// handleSnapshotReq answers a late joiner's snapshot request. Host-only.
func (c *ctlService) handleSnapshotReq(from wire.ParticipantID) error {
	if !c.Ctx().Host {
		return nil
	}
	return c.sendSnapshot(from)
}

// handleSnapshot restores per-service state from a host snapshot. Host-only
// sender; the ctl's own state never travels in snapshots.
func (c *ctlService) handleSnapshot(from wire.ParticipantID, msg ctlMsg) error {
	if from != c.Ctx().HostID {
		return fmt.Errorf("ctl: snapshot from non-host %d", from)
	}
	for id, blob := range msg.Snapshots {
		if svc, ok := c.mux.services[id]; ok && id != CtlID {
			if err := svc.Restore(blob); err != nil {
				return fmt.Errorf("ctl: restore %s: %w", id, err)
			}
		}
	}
	return nil
}

// Snapshot/Restore: the ctl's own state (the roster) travels in announces,
// not snapshots.
func (c *ctlService) Snapshot() ([]byte, error) { return nil, nil }
func (c *ctlService) Restore([]byte) error      { return nil }

// MemberKeyed / MemberLeft: host-side roster maintenance + announce.
func (c *ctlService) MemberKeyed(id wire.ParticipantID, role session.Role) {
	if !c.Ctx().Host {
		return
	}
	c.roster[id] = role
	c.announce()
}

func (c *ctlService) MemberLeft(id wire.ParticipantID) {
	if !c.Ctx().Host {
		return
	}
	delete(c.roster, id)
	delete(c.names, id)
	delete(c.endpoints, id)
	c.announce()
}

func (c *ctlService) announce() {
	roster := map[uint32]uint8{}
	for id, r := range c.roster {
		roster[uint32(id)] = uint8(r)
	}
	names := map[uint32]string{}
	endpoints := map[uint32]string{}
	for id := range c.roster { // only announce data for current members
		if n := c.names[id]; n != "" {
			names[uint32(id)] = n
		}
		if ep := c.endpoints[id]; ep != "" {
			endpoints[uint32(id)] = ep
		}
	}
	var infos []ServiceInfo
	for _, s := range c.mux.services {
		infos = append(infos, ServiceInfo{ID: s.ID(), Version: s.Version()})
	}
	body, err := wire.Marshal(ctlMsg{
		Kind: ctlKindAnnounce, Roster: roster, Names: names,
		Endpoints: endpoints, PushKey: c.pushKey, Services: infos,
	})
	if err != nil {
		return
	}
	_ = c.Ctx().Send.Broadcast(CtlID, body)
	// The host's own UI wants the roster too.
	c.mux.emit(c.roster3(infos))
}

// roster3 builds the Roster event from current state (used by both the host's
// announce and a joiner receiving one).
func (c *ctlService) roster3(infos []ServiceInfo) Roster {
	return Roster{
		Members:   c.rosterCopy(),
		Names:     c.namesCopy(),
		Endpoints: c.endpointsCopy(),
		PushKey:   c.pushKey,
		Services:  infos,
	}
}

// electSuccessor picks the host successor via the mux's SuccessorPolicy,
// handing it the roster minus the leaver. A policy result that is 0 or not
// among the candidates counts as "no successor" (guards a misbehaving
// custom policy; unreachable with DefaultSuccessorPolicy).
func (c *ctlService) electSuccessor(leaver wire.ParticipantID) wire.ParticipantID {
	candidates := make(map[wire.ParticipantID]session.Role, len(c.roster))
	for id, r := range c.roster {
		if id != leaver {
			candidates[id] = r
		}
	}
	s := c.mux.successor(candidates)
	if _, ok := candidates[s]; !ok {
		return 0
	}
	return s
}

// assumeHost makes this end the authoritative host after a migration: prune the
// departed host from the roster, mark self host, and re-announce so every
// survivor adopts the new roster + host id. The roster/names/endpoints/pushKey
// are already held from prior announces (re-announce carries them — no attribute
// regen). Runs on the mux goroutine after re-Attach set ctx.Host/HostID.
func (c *ctlService) assumeHost(leaver wire.ParticipantID) {
	delete(c.roster, leaver)
	delete(c.names, leaver)
	delete(c.endpoints, leaver)
	c.roster[c.Ctx().Self] = session.RoleHost
	c.announce()
}

func (c *ctlService) requestSnapshot() {
	body, err := wire.Marshal(ctlMsg{Kind: ctlKindSnapshotReq})
	if err != nil {
		return
	}
	_ = c.Ctx().Send.SendTo(c.Ctx().HostID, CtlID, body)
}

func (c *ctlService) sendSnapshot(to wire.ParticipantID) error {
	blobs := map[string][]byte{}
	for id, svc := range c.mux.services {
		if id == CtlID {
			continue
		}
		b, err := svc.Snapshot()
		if err != nil {
			return fmt.Errorf("ctl: snapshot %s: %w", id, err)
		}
		if len(b) > 0 {
			blobs[id] = b
		}
	}
	body, err := wire.Marshal(ctlMsg{Kind: ctlKindSnapshot, Snapshots: blobs})
	if err != nil {
		return err
	}
	return c.Ctx().Send.SendTo(to, CtlID, body)
}

func (c *ctlService) rosterCopy() map[wire.ParticipantID]session.Role {
	out := make(map[wire.ParticipantID]session.Role, len(c.roster))
	maps.Copy(out, c.roster)
	return out
}

func (c *ctlService) namesCopy() map[wire.ParticipantID]string {
	out := make(map[wire.ParticipantID]string, len(c.names))
	maps.Copy(out, c.names)
	return out
}

func (c *ctlService) endpointsCopy() map[wire.ParticipantID]string {
	out := make(map[wire.ParticipantID]string, len(c.endpoints))
	maps.Copy(out, c.endpoints)
	return out
}
