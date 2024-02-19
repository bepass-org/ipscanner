package ping

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/bepass-org/ipscanner/internal/statute"
	"github.com/davecgh/go-spew/spew"
	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

type WarpPingResult struct {
	Time int
	Err  error
	IP   netip.Addr
}

func (h *WarpPingResult) Result() int {
	return h.Time
}

func (h *WarpPingResult) Error() error {
	return h.Err
}

func (h *WarpPingResult) String() string {
	if h.Err != nil {
		return fmt.Sprintf("%s", h.Err)
	} else {
		return fmt.Sprintf("%s: protocol=%s, time=%d ms", h.IP.String(), "warp", h.Time)
	}
}

type WarpPing struct {
	PrivateKey    string
	PeerPublicKey string
	PresharedKey  string
	IP            netip.Addr

	opts statute.ScannerOptions
}

func (h *WarpPing) Ping() statute.IPingResult {
	return h.PingContext(context.Background())
}

func (h *WarpPing) PingContext(_ context.Context) statute.IPingResult {
	t0 := time.Now()
	ports := []int{500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
		943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701,
		1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279,
		5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886}

	// Pick a random port number
	b := make([]byte, 8)
	n, err := rand.Read(b)
	if n != 8 {
		panic(n)
	} else if err != nil {
		panic(err)
	}
	serverAddress := fmt.Sprintf("%s:%d", h.IP.String(), ports[int(b[0])%len(ports)])
	if strings.Contains(h.IP.String(), ":") {
		//ip6
		serverAddress = fmt.Sprintf("[%s]:%d", h.IP.String(), ports[int(b[0])%len(ports)])
	}
	err = initiateHandshake(serverAddress, h.PrivateKey, h.PeerPublicKey, h.PresharedKey)
	if err != nil {
		return h.errorResult(err)
	}
	return &WarpPingResult{int(time.Since(t0).Milliseconds()), nil, h.IP}
}

func (h *WarpPing) errorResult(err error) *WarpPingResult {
	r := &WarpPingResult{}
	r.Err = err
	return r
}

func uint32ToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}

func staticKeypair(privateKeyBase64 string) (noise.DHKey, error) {
	privateKey, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return noise.DHKey{}, err
	}

	var pubkey, privkey [32]byte
	copy(privkey[:], privateKey)
	curve25519.ScalarBaseMult(&pubkey, &privkey)

	return noise.DHKey{
		Private: privateKey,
		Public:  pubkey[:],
	}, nil
}

func ephemeralKeypair() (noise.DHKey, error) {
	// Generate an ephemeral private key
	ephemeralPrivateKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivateKey); err != nil {
		return noise.DHKey{}, err
	}

	// Derive the corresponding ephemeral public key
	ephemeralPublicKey, err := curve25519.X25519(ephemeralPrivateKey, curve25519.Basepoint)
	if err != nil {
		return noise.DHKey{}, err
	}

	return noise.DHKey{
		Private: ephemeralPrivateKey,
		Public:  ephemeralPublicKey,
	}, nil
}

func randomInt(min, max int) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		panic(err)
	}
	return int(nBig.Int64()) + min
}

func initiateHandshake(serverAddr, privateKeyBase64, peerPublicKeyBase64, presharedKeyBase64 string) error {
	staticKeyPair, err := staticKeypair(privateKeyBase64)
	if err != nil {
		return err
	}

	peerPublicKey, err := base64.StdEncoding.DecodeString(peerPublicKeyBase64)
	if err != nil {
		return err
	}

	presharedKey, err := base64.StdEncoding.DecodeString(presharedKeyBase64)
	if err != nil {
		return err
	}

	if presharedKeyBase64 == "" {
		presharedKey = make([]byte, 32)
	}

	ephemeral, err := ephemeralKeypair()
	if err != nil {
		return err
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cs,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		StaticKeypair:         staticKeyPair,
		PeerStatic:            peerPublicKey,
		Prologue:              []byte("WireGuard v1 zx2c4 Jason@zx2c4.com"),
		PresharedKey:          presharedKey,
		PresharedKeyPlacement: 2,
		EphemeralKeypair:      ephemeral,
		Random:                rand.Reader,
	})
	if err != nil {
		return err
	}

	// Prepare handshake initiation packet

	// TAI64N timestamp calculation
	now := time.Now().UTC()
	epochOffset := int64(4611686018427387914) // TAI offset from Unix epoch

	tai64nTimestampBuf := make([]byte, 0, 16)
	tai64nTimestampBuf = binary.BigEndian.AppendUint64(tai64nTimestampBuf, uint64(epochOffset+now.Unix()))
	tai64nTimestampBuf = binary.BigEndian.AppendUint32(tai64nTimestampBuf, uint32(now.Nanosecond()))
	msg, _, _, err := hs.WriteMessage(nil, tai64nTimestampBuf)
	if err != nil {
		return err
	}

	initiationPacket := new(bytes.Buffer)
	binary.Write(initiationPacket, binary.BigEndian, []byte{0x01, 0x00, 0x00, 0x00})
	binary.Write(initiationPacket, binary.BigEndian, uint32ToBytes(28))
	binary.Write(initiationPacket, binary.BigEndian, msg)

	macKey := blake2s.Sum256(append([]byte("mac1----"), peerPublicKey...))
	hasher, err := blake2s.New128(macKey[:]) // using macKey as the key
	if err != nil {
		return err
	}
	_, err = hasher.Write(initiationPacket.Bytes())
	if err != nil {
		return err
	}
	initiationPacketMAC := hasher.Sum(nil)

	// Append the MAC and 16 null bytes to the initiation packet
	binary.Write(initiationPacket, binary.BigEndian, initiationPacketMAC[:16])
	binary.Write(initiationPacket, binary.BigEndian, [16]byte{})

	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Generate a random number of packets between 5 and 10
	numPackets := randomInt(1, 2)
	for i := 0; i < numPackets; i++ {
		// Generate a random packet size between 10 and 40 bytes
		packetSize := randomInt(1, 100)
		randomPacket := make([]byte, packetSize)
		_, err := rand.Read(randomPacket)
		if err != nil {
			return fmt.Errorf("error generating random packet: %v", err)
		}

		// Send the random packet
		_, err = conn.Write(randomPacket)
		if err != nil {
			return fmt.Errorf("error sending random packet: %v", err)
		}

		// Wait for a random duration between 200 and 500 milliseconds
		time.Sleep(time.Duration(randomInt(200, 500)) * time.Millisecond)
	}

	// spew.Dump(initiationPacket)
	_, err = initiationPacket.WriteTo(conn)
	if err != nil {
		return err
	}

	response := make([]byte, 92)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	i, err := conn.Read(response)
	fmt.Println("server response, len+packet: ", i, response[12:60])
	if err != nil {
		return err
	}

	// Check the response type
	if response[0] != 2 { // 2 is the message type for response
		return errors.New("invalid response type")
	}

	// Extract sender and receiver index from the response
	// peer index
	_ = binary.LittleEndian.Uint32(response[4:8])
	// our index(we set it to 28)
	ourIndex := binary.LittleEndian.Uint32(response[8:12])
	if ourIndex != 28 { // Check if the response corresponds to our sender index
		return errors.New("invalid sender index in response")
	}

	payload, _, _, err := hs.ReadMessage(nil, response[12:60])
	spew.Dump(payload)
	if err != nil {
		spew.Dump(err)
		return err
	}

	// Check if the payload is empty (as expected in WireGuard handshake)
	if len(payload) != 0 {
		return errors.New("unexpected payload in response")
	}

	fmt.Println("Handshake completed successfully")
	return nil
}

func NewWarpPing(ip netip.Addr, opts *statute.ScannerOptions) *WarpPing {
	return &WarpPing{
		PrivateKey:    opts.WarpPrivateKey,
		PeerPublicKey: opts.WarpPeerPublicKey,
		PresharedKey:  opts.WarpPresharedKey,
		IP:            ip,

		opts: *opts,
	}
}

var (
	_ statute.IPing       = (*WarpPing)(nil)
	_ statute.IPingResult = (*WarpPingResult)(nil)
)
