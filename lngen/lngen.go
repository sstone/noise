package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/roasbeef/btcd/btcec"
	. "github.com/sstone/noise"
)

// SECP256k1Alt is our alternate secp256k1 ECDH function.
var SECP256k1Alt DHFunc = secp256k1Alt{}

type secp256k1Alt struct{}

func (secp256k1Alt) GenerateKeypair(rng io.Reader) DHKey {
	var privkey [32]byte
	if rng == nil {
		rng = rand.Reader
	}
	if _, err := io.ReadFull(rng, privkey[:]); err != nil {
		panic(err)
	}
	_, pub := btcec.PrivKeyFromBytes(btcec.S256(), privkey[:])
	pubkey := pub.SerializeCompressed()
	//fmt.Fprintf(os.Stdout, "priv=%x pub=%x\n", privkey, pubkey)

	return DHKey{Private: privkey[:], Public: pubkey[:]}
}

func (secp256k1Alt) DH(privkey, pubkey []byte) []byte {
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), privkey)
	pub, err := btcec.ParsePubKey(pubkey, btcec.S256())
	if err != nil {
		fmt.Printf("error %v\n", err)
	}
	x, y := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	pub.X = x
	pub.Y = y
	return pub.SerializeCompressed()
}

func (secp256k1Alt) DHLen() int     { return 33 }
func (secp256k1Alt) PubLen() int    { return 33 }
func (secp256k1Alt) DHName() string { return "secp256k1" }

// SECP256k1 is the secp256k1 ECDH function specified by Laolu
var SECP256k1 DHFunc = secp256k1{}

type secp256k1 struct{}

func (secp256k1) GenerateKeypair(rng io.Reader) DHKey {
	var privkey [32]byte
	if rng == nil {
		rng = rand.Reader
	}
	if _, err := io.ReadFull(rng, privkey[:]); err != nil {
		panic(err)
	}
	_, pub := btcec.PrivKeyFromBytes(btcec.S256(), privkey[:])
	pubkey := pub.SerializeCompressed()

	return DHKey{Private: privkey[:], Public: pubkey[:]}
}

func (secp256k1) DH(privkey, pubkey []byte) []byte {
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), privkey)
	pub, err := btcec.ParsePubKey(pubkey, btcec.S256())
	if err != nil {
		fmt.Printf("error %v\n", err)
	}
	return btcec.GenerateSharedSecret(priv, pub)
}

func (secp256k1) DHLen() int     { return 32 }
func (secp256k1) PubLen() int    { return 33 }
func (secp256k1) DHName() string { return "secp256k1" }

// SECP256k1Rusty is the secp256k1 ECDH function.
var SECP256k1Rusty DHFunc = secp256k1Rusty{}

type secp256k1Rusty struct{}

func (secp256k1Rusty) GenerateKeypair(rng io.Reader) DHKey {
	var privkey [32]byte
	if rng == nil {
		rng = rand.Reader
	}
	if _, err := io.ReadFull(rng, privkey[:]); err != nil {
		panic(err)
	}
	_, pub := btcec.PrivKeyFromBytes(btcec.S256(), privkey[:])
	pubkey := pub.SerializeCompressed()
	//fmt.Fprintf(os.Stdout, "priv=%x pub=%x\n", privkey, pubkey)

	return DHKey{Private: privkey[:], Public: pubkey[:]}
}

func (secp256k1Rusty) DH(privkey, pubkey []byte) []byte {
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), privkey)
	pub, err := btcec.ParsePubKey(pubkey, btcec.S256())
	if err != nil {
		fmt.Printf("error %v\n", err)
	}
	x, y := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	pub.X = x
	pub.Y = y
	sha256 := HashSHA256.Hash()
	sha256.Write(pub.SerializeCompressed())
	return sha256.Sum(nil)
}

func (secp256k1Rusty) DHLen() int     { return 32 }
func (secp256k1Rusty) PubLen() int    { return 33 }
func (secp256k1Rusty) DHName() string { return "secp256k1" }
func main() {
	writeHandshake(os.Stdout, NewCipherSuite(SECP256k1Rusty, CipherChaChaPoly, HashSHA256), HandshakeXK, false, true, false)
}

func hexReader(s string) io.Reader {
	res, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes.NewBuffer(res)
}

const (
	key0 = "1111111111111111111111111111111111111111111111111111111111111111"
	key1 = "2121212121212121212121212121212121212121212121212121212121212121"
	key2 = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	key3 = "1212121212121212121212121212121212121212121212121212121212121212"
	key4 = "2222222222222222222222222222222222222222222222222222222222222222"
)

func writeHandshake(out io.Writer, cs CipherSuite, h HandshakePattern, hasPSK, hasPrologue, payloads bool) {
	var prologue, psk []byte
	if hasPrologue {
		prologue = []byte("lightning")
	}
	if hasPSK {
		psk = []byte("lightning")
	}

	staticI := cs.GenerateKeypair(hexReader(key0))
	staticR := cs.GenerateKeypair(hexReader(key1))
	ephR := cs.GenerateKeypair(hexReader(key2))

	configI := Config{
		CipherSuite:  cs,
		Random:       hexReader(key3),
		Pattern:      h,
		Initiator:    true,
		Prologue:     prologue,
		PresharedKey: psk,
	}
	configR := configI
	configR.Random = hexReader(key4)
	configR.Initiator = false

	var pskName string
	if hasPSK {
		pskName = "PSK"
	}

	fmt.Fprintf(out, "handshake=Noise%s_%s_%s\n", pskName, h.Name, cs.Name())

	if len(h.Name) == 1 {
		switch h.Name {
		case "N":
			configR.StaticKeypair = staticR
			configI.PeerStatic = staticR.Public
			fmt.Fprintf(out, "resp_static=%x\n", staticR.Private)
		case "K":
			configI.StaticKeypair = staticI
			configR.PeerStatic = staticI.Public
			configR.StaticKeypair = staticR
			configI.PeerStatic = staticR.Public
			fmt.Fprintf(out, "init_static=%x\n", staticI.Private)
			fmt.Fprintf(out, "resp_static=%x\n", staticR.Private)
		case "X":
			configI.StaticKeypair = staticI
			configR.StaticKeypair = staticR
			configI.PeerStatic = staticR.Public
			fmt.Fprintf(out, "init_static=%x\n", staticI.Private)
			fmt.Fprintf(out, "resp_static=%x\n", staticR.Private)
		}
	} else {
		switch h.Name[0] {
		case 'K', 'X', 'I':
			configI.StaticKeypair = staticI
			if h.Name[0] == 'K' {
				configR.PeerStatic = staticI.Public
			}
			fmt.Fprintf(out, "init_static=%x\n", staticI.Private)
		}
		switch h.Name[1] {
		case 'K', 'E', 'X', 'R':
			configR.StaticKeypair = staticR
			fmt.Fprintf(out, "resp_static=%x\n", staticR.Private)
			switch h.Name[1] {
			case 'K':
				configI.PeerStatic = staticR.Public
			case 'E':
				configR.EphemeralKeypair = ephR
				configI.PeerEphemeral = ephR.Public
				configI.PeerStatic = staticR.Public
				fmt.Fprintf(out, "resp_ephemeral=%x\n", ephR.Private)
			}
		}
	}

	fmt.Fprintf(out, "gen_init_ephemeral=%s\n", key3)
	fmt.Fprintf(out, "gen_resp_ephemeral=%s\n", key4)
	if len(prologue) > 0 {
		fmt.Fprintf(out, "prologue=%x\n", prologue)
	}
	if len(psk) > 0 {
		fmt.Fprintf(out, "preshared_key=%x\n", psk)
	}

	hsI := NewHandshakeState(configI)
	hsR := NewHandshakeState(configR)

	var cs0, cs1 *CipherState
	for i := range h.Messages {
		writer, reader := hsI, hsR
		if i%2 != 0 {
			writer, reader = hsR, hsI
		}

		var payload string
		if payloads {
			payload = fmt.Sprintf("test_msg_%d", i)
		}
		var msg []byte
		msg, cs0, cs1 = writer.WriteMessage(nil, []byte(payload))
		_, _, _, err := reader.ReadMessage(nil, msg)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(out, "msg_%d_payload=%x\n", i, payload)
		fmt.Fprintf(out, "msg_%d_ciphertext=%x\n", i, msg)
	}
	payload0 := []byte("yellowsubmarine")
	payload1 := []byte("submarineyellow")
	fmt.Fprintf(out, "msg_%d_payload=%x\n", len(h.Messages), payload0)
	fmt.Fprintf(out, "msg_%d_ciphertext=%x\n", len(h.Messages), cs0.Encrypt(nil, nil, payload0))
	fmt.Fprintf(out, "msg_%d_payload=%x\n", len(h.Messages)+1, payload1)
	fmt.Fprintf(out, "msg_%d_ciphertext=%x\n", len(h.Messages)+1, cs1.Encrypt(nil, nil, payload1))
}
