// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

func TestSignAndVerify(t *testing.T) {
	t.Run("es256", func(t *testing.T) {
		// Test from https://github.com/cose-wg/Examples/blob/b7a0a92bcdcba1e35c2075140e0c7c64e6e13551/sign1-tests/sign-pass-02.json
		x, _ := base64.RawURLEncoding.DecodeString("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
		y, _ := base64.RawURLEncoding.DecodeString("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
		d, _ := base64.RawURLEncoding.DecodeString("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM")
		key256 := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			},
			D: new(big.Int).SetBytes(d),
		}
		data, _ := hex.DecodeString("d28443a10126a10442313154546869732069732074686520636f6e74656e742e584010729cd711cb3813d8d8e944a8da7111e7b258c9bdca6135f7ae1adbee9509891267837e1e33bd36c150326ae62755c6bd8e540c3e8f92d7d225e8db72b8820b")

		s1 := cose.Sign1[[]byte, []byte]{
			Header: cose.Header{
				Unprotected: cose.HeaderMap{
					cose.Label{Int64: 4}: []byte("11"),
				},
			},
			Payload: cbor.NewByteWrap([]byte("This is the content.")),
		}

		externalAAD, _ := hex.DecodeString("11aa22bb33cc44dd55006699")

		if err := s1.Sign(key256, nil, externalAAD, nil); err != nil {
			t.Fatalf("error signing: %v", err)
		}
		if len(s1.Signature) != 64 {
			t.Fatalf("signature length correct: expected %d, got %d", 64, len(s1.Signature))
		}

		// Unmarshal from test case
		var s1t cose.Sign1Tag[[]byte, []byte]
		if err := cbor.Unmarshal(data, &s1t); err != nil {
			t.Fatalf("error unmarshaling: %v", err)
		}

		passed, err := s1t.Verify(key256.Public(), nil, externalAAD)
		if err != nil {
			t.Fatalf("error verifying: %v", err)
		}
		if !passed {
			t.Fatal("verification failed")
		}
	})

	t.Run("es384", func(t *testing.T) {
		key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Errorf("error generating ec key p384: %v", err)
			return
		}

		s1 := cose.Sign1[[]byte, []byte]{
			Payload: cbor.NewByteWrap([]byte("This is the content.")),
		}
		if err := s1.Sign(key384, nil, nil, nil); err != nil {
			t.Fatalf("error signing: %v", err)
		}
		if len(s1.Signature) != 96 {
			t.Fatalf("signature length correct: expected %d, got %d", 96, len(s1.Signature))
		}

		// Marshal and Unmarshal
		data, err := cbor.Marshal(s1)
		if err != nil {
			t.Fatalf("error marshaling: %v", err)
		}
		var s1a cose.Sign1[[]byte, []byte]
		if err := cbor.Unmarshal(data, &s1a); err != nil {
			t.Fatalf("error unmarshaling: %v", err)
		}

		passed, err := s1a.Verify(key384.Public(), nil, nil)
		if err != nil {
			t.Fatalf("error verifying: %v", err)
		}
		if !passed {
			t.Fatal("verification failed")
		}
	})
}

func TestSomethingThatFailedSignatureVerificationOnceInCIForUnknownReasons(t *testing.T) {
	// 18([h'a101390100', {256: h'b2d33efa8e5cea10ea364043bc381bc3', 257: [1, 1, h'30820122300d06092a864886f70d01010105000382010f003082010a0282010100d3e882bc85ebe378b5c043f5f51135f39531c5708fb0a455fb680eff25070502ad3f333de6e1bbaac4c133107f125c8056047d4c77dbdde178eb92b43432f249f7ca080be18b04662d03f4d28873b9569094d50b036d4b8b65eee101ec54b2f834a45e4e297464dc231c74e643ec99fa84b49363d3aa7bb5e73aa96b0c74c886c132f997aea110b4f5b89451a52bfa651d50fcabfde7fb570a99f744f849afdc27732f5bdee138ea2d2ae0e95bc010eae36c9eee7286cc615844d7a84946d4b8c6653563004b528771734f30bff2af9c699d9cf23477663c231f936670aa64bbdd4ab4367a62ab34a5dfb44ca03d4ecc74c28e33803b3ca4a04c0271bbe6d1ad0203010001']}, h'8859017186186550ed5c309ac00d13f29b22912649fac98e806b746573745f64657669636583010159012630820122300d06092a864886f70d01010105000382010f003082010a0282010100d3e882bc85ebe378b5c043f5f51135f39531c5708fb0a455fb680eff25070502ad3f333de6e1bbaac4c133107f125c8056047d4c77dbdde178eb92b43432f249f7ca080be18b04662d03f4d28873b9569094d50b036d4b8b65eee101ec54b2f834a45e4e297464dc231c74e643ec99fa84b49363d3aa7bb5e73aa96b0c74c886c132f997aea110b4f5b89451a52bfa651d50fcabfde7fb570a99f744f849afdc27732f5bdee138ea2d2ae0e95bc010eae36c9eee7286cc615844d7a84946d4b8c6653563004b528771734f30bff2af9c699d9cf23477663c231f936670aa64bbdd4ab4367a62ab34a5dfb44ca03d4ecc74c28e33803b3ca4a04c0271bbe6d1ad0203010001822f58209f17599e0a16082abaf313f448add12acd14c981a3dfa786d240c842113d974000820558206552c303917e65450b187727bb6df531c819421e7148790c045b52dcc1dfbc9d509b5473c6ed93fd29c5507fafc0b5824082390100405820829da9590248b6b8f9b559bb2b5bac3ce88984963fc0fae842a5b5f07c3b15e5822f58206ebb2e1467c7162bb953c36092ad805207a8474ccd18b06267198b184c34eaf419ffff', h'881e74d84932c8986341f8423801f43aab92a813f53ee9902cc5d2ebf48f4ea23ca84fe52f709b1c86b6a17295b605b5d5d1e876069cc0bb7fd9115f16f6e7aceb43c4997053161ca1117110e24ea83afb9bf2092dc1e921dac0ecd533fd33b1e6f6e48a04d085d8a3b9552c6a447f39249509de11d2a52f09b13736d0fee2afe63af26ac6a56b615ed7f937b6b087a3d1105c0e07326cd76c8974e12f75c6dc91b18ec08cdded88b9b32b803becb37757210682c9d975be507c8364ad4ae99e5a903db04ab5f94baa039168d070f641f3685437f32972cb79d4f92fcdc47045d9cdcb9385de1dce1421d3cbf09cd73d34775775e4300c7454ada07c92d38613'])
	data, _ := hex.DecodeString("D28445A101390100A219010050B2D33EFA8E5CEA10EA364043BC381BC319010183010159012630820122300D06092A864886F70D01010105000382010F003082010A0282010100D3E882BC85EBE378B5C043F5F51135F39531C5708FB0A455FB680EFF25070502AD3F333DE6E1BBAAC4C133107F125C8056047D4C77DBDDE178EB92B43432F249F7CA080BE18B04662D03F4D28873B9569094D50B036D4B8B65EEE101EC54B2F834A45E4E297464DC231C74E643EC99FA84B49363D3AA7BB5E73AA96B0C74C886C132F997AEA110B4F5B89451A52BFA651D50FCABFDE7FB570A99F744F849AFDC27732F5BDEE138EA2D2AE0E95BC010EAE36C9EEE7286CC615844D7A84946D4B8C6653563004B528771734F30BFF2AF9C699D9CF23477663C231F936670AA64BBDD4AB4367A62AB34A5DFB44CA03D4ECC74C28E33803B3CA4A04C0271BBE6D1AD02030100015901F98859017186186550ED5C309AC00D13F29B22912649FAC98E806B746573745F64657669636583010159012630820122300D06092A864886F70D01010105000382010F003082010A0282010100D3E882BC85EBE378B5C043F5F51135F39531C5708FB0A455FB680EFF25070502AD3F333DE6E1BBAAC4C133107F125C8056047D4C77DBDDE178EB92B43432F249F7CA080BE18B04662D03F4D28873B9569094D50B036D4B8B65EEE101EC54B2F834A45E4E297464DC231C74E643EC99FA84B49363D3AA7BB5E73AA96B0C74C886C132F997AEA110B4F5B89451A52BFA651D50FCABFDE7FB570A99F744F849AFDC27732F5BDEE138EA2D2AE0E95BC010EAE36C9EEE7286CC615844D7A84946D4B8C6653563004B528771734F30BFF2AF9C699D9CF23477663C231F936670AA64BBDD4AB4367A62AB34A5DFB44CA03D4ECC74C28E33803B3CA4A04C0271BBE6D1AD0203010001822F58209F17599E0A16082ABAF313F448ADD12ACD14C981A3DFA786D240C842113D974000820558206552C303917E65450B187727BB6DF531C819421E7148790C045B52DCC1DFBC9D509B5473C6ED93FD29C5507FAFC0B5824082390100405820829DA9590248B6B8F9B559BB2B5BAC3CE88984963FC0FAE842A5B5F07C3B15E5822F58206EBB2E1467C7162BB953C36092AD805207A8474CCD18B06267198B184C34EAF419FFFF590100881E74D84932C8986341F8423801F43AAB92A813F53EE9902CC5D2EBF48F4EA23CA84FE52F709B1C86B6A17295B605B5D5D1E876069CC0BB7FD9115F16F6E7ACEB43C4997053161CA1117110E24EA83AFB9BF2092DC1E921DAC0ECD533FD33B1E6F6E48A04D085D8A3B9552C6A447F39249509DE11D2A52F09B13736D0FEE2AFE63AF26AC6A56B615ED7F937B6B087A3D1105C0E07326CD76C8974E12F75C6DC91B18EC08CDDED88B9B32B803BECB37757210682C9D975BE507C8364AD4AE99E5A903DB04AB5F94BAA039168D070F641F3685437F32972CB79D4F92FCDC47045D9CDCB9385DE1DCE1421D3CBF09CD73D34775775E4300C7454ADA07C92D38613")
	type ovhProof struct {
		OVH             cbor.Bstr[fdo.VoucherHeader]
		NumOVEntries    uint8
		OVHHmac         protocol.Hmac
		NonceTO2ProveOV protocol.Nonce
		SigInfoB        struct {
			Type cose.SignatureAlgorithm
			Info []byte
		}
		KeyExchangeA        []byte
		HelloDeviceHash     protocol.Hash
		MaxOwnerMessageSize uint16
	}
	var proveOVHdr cose.Sign1Tag[ovhProof, []byte]
	if err := cbor.Unmarshal(data, &proveOVHdr); err != nil {
		t.Fatal(err)
	}

	var ownerPubKey protocol.PublicKey
	if ok, err := proveOVHdr.Unprotected.Parse(cose.Label{Int64: 257}, &ownerPubKey); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expected pub key in unprotected header")
	}

	key, err := ownerPubKey.Public()
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := proveOVHdr.Verify(key, nil, nil); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("verification failed")
	}
}
