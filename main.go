package main

import (
	"fmt"
	"math/big"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/simple"
)

const (
	VEC_LEN = 12
	MOD_LEN = 128
)

var BOUND = new(big.Int).SetUint64(1 << 32) // 2^32

type DDH struct {
	*simple.DDH
	msk data.Vector
	mpk data.Vector
}

func NewDDH() *DDH {
	ddh, err := simple.NewDDH(VEC_LEN, MOD_LEN, BOUND)
	if err != nil {
		panic(err)
	}
	return &DDH{ddh, nil, nil}
}

func (e *DDH) Init() error {
	msk, mpk, err := e.GenerateMasterKeys()
	if err != nil {
		return err
	}
	e.msk = msk
	e.mpk = mpk
	return nil
}

func (e *DDH) GetFeKey(x, y []int) (*big.Int, error) {
	if len(x) != len(y) {
		return nil, fmt.Errorf("slice lengths do not match")
	}

	//bigX := make([]*big.Int, len(x))
	bigY := make([]*big.Int, len(y))
	for i := 0; i < len(x); i++ {
		//bigX[i] = new(big.Int).SetInt64(int64(x[i]))
		bigY[i] = new(big.Int).SetInt64(int64(y[i]))
	}

	//vecX := data.NewVector(bigX)
	vecY := data.NewVector(bigY)

	feKey, err := e.DeriveKey(e.msk, vecY)
	if err != nil {
		return nil, err
	}

	return feKey, nil
}

func (e *DDH) PrintParams() {
	fmt.Printf("DDH (s-IND-CPA):\n"+
		"\tL: %d\n"+
		"\tG: %d\n"+
		"\tP: %d\n"+
		"\tQ: %d\n"+
		"\tBound: %d\n",
		e.Params.L, e.Params.G, e.Params.P, e.Params.Q, e.Params.Bound)
}

func main() {
	ddh := NewDDH()
	ddh.PrintParams()
	if err := ddh.Init(); err != nil {
		panic("Failed to initialize DDH:" + err.Error())
	}

	fmt.Printf("MSK: %s\nMPK: %s\n", msk, mpk)

	ddh.DeriveKey()
}
