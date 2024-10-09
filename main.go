package main

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/innerprod/simple"
)

// Parameters for the DDH scheme
const ModLen = 64     // Length of the modulus (bits)
const Bound = 1 << 16 // Input vector bound

// DDHWrapper is a wrapper around the simple.DDH struct, providing some convenience methods.
type DDHWrapper struct {
	*simple.DDH
	msk data.Vector
	mpk data.Vector
}

// NewDDH creates a new DDHWrapper instance.
func NewDDH(vecLen int) (*DDHWrapper, error) {
	ddh, err := simple.NewDDH(vecLen, ModLen, new(big.Int).SetUint64(Bound))
	if err != nil {
		return nil, err
	}

	w := &DDHWrapper{ddh, nil, nil}
	msk, mpk, err := ddh.GenerateMasterKeys()
	if err != nil {
		return nil, err
	}
	w.msk = msk
	w.mpk = mpk
	return w, err
}

// Encrypt calls the Encrypt method of the embedded DDH scheme with the stored keys.
func (e *DDHWrapper) Encrypt(x data.Vector) (data.Vector, error) {
	return e.DDH.Encrypt(x, e.mpk)
}

// DeriveKey calls the method of the embedded DDH scheme with the stored keys.
func (e *DDHWrapper) DeriveKey(y data.Vector) (*big.Int, error) {
	return e.DDH.DeriveKey(e.msk, y)
}

func (e *DDHWrapper) ExportKeys() (string, string) {
	var mskS []string
	for _, v := range e.msk {
		mskS = append(mskS, v.String())
	}

	var mpkS []string
	for _, v := range e.mpk {
		mpkS = append(mpkS, v.String())
	}

	return strings.Join(mskS, "-"), strings.Join(mpkS, "-")
}

// PrintParams prints the parameters the DDH scheme was initialized with.
func (e *DDHWrapper) PrintParams() {
	fmt.Printf("DDHWrapper (s-IND-CPA):\n"+
		"\tL: %d\n"+
		"\tG: %d\n"+
		"\tP: %d\n"+
		"\tQ: %d\n"+
		"\tBound: %d\n",
		e.Params.L, e.Params.G, e.Params.P, e.Params.Q, e.Params.Bound)
}

// IntsToVec converts a slice of ints to a data.Vector used by the fentec-project/gofe module.
func IntsToVec(x []int) data.Vector {
	bigX := make([]*big.Int, len(x))
	for i := range x {
		bigX[i] = new(big.Int).SetInt64(int64(x[i]))
	}
	return data.NewVector(bigX)
}

// VecFromStr converts a comma-separated string of integers to a data.Vector.
func VecFromStr(s string) (data.Vector, error) {
	split := strings.Split(s, ",")
	x := make([]*big.Int, len(split))
	for i := range split {
		n, err := strconv.ParseUint(split[i], 10, 64)
		if err != nil {
			return nil, err
		}
		x[i] = new(big.Int).SetUint64(n)
	}
	return data.NewVector(x), nil
}

func main() {
	// Get user input
	for {
		fmt.Print("Enter the first vector <x> as comma-separated integers (e.g. <5,128,1,48,3>): ")
		var xInput string
		n, err := fmt.Scanln(&xInput)
		if err != nil || n == 0 {
			fmt.Printf("Error reading input, please try again (%s)\n", err)
			continue
		}

		// Parse the input
		vecX, err := VecFromStr(xInput)
		if err != nil {
			fmt.Printf("Error parsing input: %s\n", err)
			continue
		}
		if len(vecX) < 2 {
			fmt.Println("Vector should have at least 2 elements.")
			continue
		}

		fmt.Print("Enter the second vector <y>: ")
		var yInput string
		n, err = fmt.Scanln(&yInput)
		if err != nil || n == 0 {
			fmt.Printf("Error reading input, please try again (%s)\n", err)
			continue
		}

		// Parse the input
		vecY, err := VecFromStr(yInput)
		if err != nil {
			fmt.Printf("Error parsing input: %s\n", err)
			continue
		}
		if len(vecX) < 2 {
			fmt.Println("Vector should have at least 2 elements.")
			continue
		}

		if len(vecX) != len(vecY) {
			fmt.Printf("Vectors should be of the same length, please try again.\n")
			continue
		}

		// Create a new DDHWrapper instance
		ddh, err := NewDDH(len(vecX))
		if err != nil {
			fmt.Printf("Failed to create DDHWrapper: %s\n", err)
			continue
		}
		fmt.Println("\n------------------------\nDDHWrapper created successfully.")
		ddh.PrintParams()
		msk, mpk := ddh.ExportKeys()
		fmt.Printf("Master secret key: %s\nMaster public key: %s\n", msk, mpk)
		fmt.Println("------------------------\n")

		// Encrypt the first vector
		c, err := ddh.Encrypt(vecX)
		if err != nil {
			fmt.Printf("Failed to encrypt vector: %s\n", err)
			continue
		}
		fmt.Printf("Encrypted vector: [%s]\n", c)

		// Derive the functional encryption key
		feKey, err := ddh.DeriveKey(vecY)
		if err != nil {
			fmt.Printf("Failed to derive functional encryption key: %s\n", err)
			continue
		}
		fmt.Printf("Functional encryption key: %s\n", feKey)

		// Decrypt the encrypted vector with the derived key
		dec, err := ddh.Decrypt(c, feKey, vecY)
		if err != nil {
			fmt.Printf("Failed to decrypt: %s\n", err)
			continue
		}
		fmt.Printf("Decrypted inner product: %s\n", dec)

		// Calculate the inner product to verify the decryption
		innerProd := big.NewInt(0)
		for i := range vecX {
			innerProd.Add(innerProd, new(big.Int).Mul(vecX[i], vecY[i]))
		}

		if innerProd.Cmp(dec) == 0 {
			fmt.Println("Inner product check 🆗")
		} else {
			fmt.Printf("Inner product check failed: %d != %d\n", innerProd, dec)
		}

		fmt.Print("Do you want to try again? (y/n): ")
		var tryAgain string
		n, err = fmt.Scanln(&tryAgain)
		if err != nil || n == 0 {
			fmt.Printf("Error reading input, please try again (%s)", err)
			continue
		}
		if strings.ToLower(tryAgain) != "y" {
			break
		} else {
			fmt.Println("\n~\n")
		}
	}
}
