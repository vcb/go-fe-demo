package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/simple"
)

// NOTE: does not test the usage itself, only the API
func TestDDHMulti(t *testing.T) {
	numClients := 3
	vecLen := 32
	bound := new(big.Int).SetUint64(1 << 16)

	ddh, err := simple.NewDDHMulti(numClients, vecLen, 128, bound)
	if err != nil {
		t.Fatal(err)
	}

	mpk, msk, err := ddh.GenerateMasterKeys()
	if err != nil {
		t.Fatal(err)
	}

	clients := make([]*simple.DDHMultiClient, numClients)
	for i := range clients {
		clients[i] = simple.NewDDHMultiClient(ddh.Params)
	}

	ciphers := make([]data.Vector, numClients)
	for i := range clients {
		vecX := RandomVec(vecLen, bound)

		c, err := clients[i].Encrypt(vecX, mpk[i], msk.OtpKey[i])
		if err != nil {
			t.Fatal(err)
		}
		ciphers[i] = c
	}

	vecY := RandomVec(vecLen, bound)

	vecs := make([]data.Vector, numClients)
	for i := range vecs {
		vecs[i] = vecY
	}
	matY, err := data.NewMatrix(vecs)
	if err != nil {
		t.Fatalf("Failed to create matrix: %s", err)
	}

	feKey, err := ddh.DeriveKey(msk, matY)
	if err != nil {
		t.Fatalf("Failed to derive key: %s", err)
	}

	fDec, err := ddh.Decrypt(ciphers, feKey, matY)
	if err != nil {
		t.Fatalf("Failed to decrypt: %s", err)
	}

	t.Logf("Decrypted inner product: %s", fDec)
}

/*
	var params []struct {
		name   string
		vecLen int
		modLen int
		bound  *big.Int
	}

	for _, vecLen := range []int{2, 5, 10} {
		for _, modLen := range []int{32, 64, 128} {
			for _, bound := range []uint64{1 << 8, 1 << 16, 1 << 32} {
				params = append(params, struct {
					name   string
					vecLen int
					modLen int
					bound  *big.Int
				}{
					name:   fmt.Sprintf("%d_%d_%d", vecLen, modLen, bound),
					vecLen: vecLen,
					modLen: modLen,
					bound:  new(big.Int).SetUint64(bound),
				})
			}
		}
	}
*/

func BenchmarkDDHKeyGen(b *testing.B) {
	var params []struct {
		name   string
		modLen int
	}

	for _, modLen := range []int{32, 64, 128, 256, 512} {
		params = append(params, struct {
			name   string
			modLen int
		}{
			name:   fmt.Sprintf("%d", modLen),
			modLen: modLen,
		})
	}

	for _, bm := range params {
		b.Run(bm.name, func(b *testing.B) {
			var err error
			ddh, err := simple.NewDDH(2, ModLen, new(big.Int).SetUint64(Bound))
			if err != nil {
				b.Fatal(err)
			}

			for i := 0; i < b.N; i++ {
				_, _, err = ddh.GenerateMasterKeys()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func RandomVec(len int, bound *big.Int) data.Vector {
	coords := make([]*big.Int, len)
	for i := range len {
		var n uint64
		err := binary.Read(rand.Reader, binary.LittleEndian, &n)
		if err != nil {
			panic(err)
		}
		coords[i] = new(big.Int).Mod(new(big.Int).SetUint64(n), bound)
	}
	return data.NewVector(coords)
}

type TestParams struct {
	name   string
	vecLen int
	modLen int
	bound  *big.Int
}

func DDHTestParams() []TestParams {
	var params []TestParams

	for _, modLen := range []int{64} {
		for _, bound := range []uint64{1 << 16} {
			for _, vecLen := range []int{1, 3, 5, 10, 15} {
				params = append(params, TestParams{
					name:   fmt.Sprintf("%d_%d_%d", vecLen, modLen, bound),
					vecLen: vecLen,
					modLen: modLen,
					bound:  new(big.Int).SetUint64(bound),
				})
			}
		}
	}
	return params
}

func BenchmarkDDHEncrypt(b *testing.B) {
	params := DDHTestParams()

	for _, bm := range params {
		b.Run(bm.name, func(b *testing.B) {
			var err error
			ddh, err := simple.NewDDH(bm.vecLen, bm.modLen, bm.bound)
			if err != nil {
				b.Fatal(err)
			}

			_, mpk, err := ddh.GenerateMasterKeys()
			if err != nil {
				b.Fatal(err)
			}

			x := RandomVec(bm.vecLen, bm.bound)

			for i := 0; i < b.N; i++ {
				_, err = ddh.Encrypt(x, mpk)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDDHDecrypt(b *testing.B) {
	params := DDHTestParams()

	for _, bm := range params {
		b.Run(bm.name, func(b *testing.B) {
			var err error
			ddh, err := simple.NewDDH(bm.vecLen, bm.modLen, bm.bound)
			if err != nil {
				b.Fatal(err)
			}

			msk, mpk, err := ddh.GenerateMasterKeys()
			if err != nil {
				b.Fatal(err)
			}

			x := RandomVec(bm.vecLen, bm.bound)
			y := RandomVec(bm.vecLen, bm.bound)

			feKey, err := ddh.DeriveKey(msk, y)
			if err != nil {
				b.Fatal(err)
			}

			c, err := ddh.Encrypt(x, mpk)
			if err != nil {
				b.Fatal(err)
			}

			for i := 0; i < b.N; i++ {
				_, err = ddh.Decrypt(c, feKey, y)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
