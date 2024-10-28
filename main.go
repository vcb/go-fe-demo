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

func PrintParams(p *simple.DDHParams) {
	fmt.Printf("DDH:\n"+
		"\tL: %d\n"+
		"\tG: %d\n"+
		"\tP: %d\n"+
		"\tQ: %d\n"+
		"\tBound: %d\n",
		p.L, p.G, p.P, p.Q, p.Bound)
}

// IntsToVec converts a slice of ints to a data.Vector
func IntsToVec(x []int) data.Vector {
	bigX := make([]*big.Int, len(x))
	for i := range x {
		bigX[i] = new(big.Int).SetInt64(int64(x[i]))
	}
	return data.NewVector(bigX)
}

// VecFromStr converts a comma-separated string of integers to a data.Vector
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
		fmt.Printf("Schemes:\n" + "\t (1) DDH (s-IND-CPA)\n" + "\t (2) MultiDDH (s-IND-CPA)\n" + "Enter the number of the scheme you want to use: ")
		var scheme int
		n, err := fmt.Scanln(&scheme)
		if err != nil || n == 0 {
			fmt.Printf("Error reading input, please try again (%s)\n", err)
			continue
		}

		switch scheme {
		case 1:
			fmt.Println("Selected scheme: DDH (s-IND-CPA), using default parameters.")
			cliDDH()
		case 2:
			fmt.Println("Selected scheme: MultiDDH (s-IND-CPA), using default parameters.")
			cliMultiDDH()
		default:
			fmt.Println("Invalid selection, please try again.")
			continue
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
			fmt.Printf("\n~\n\n")
		}
	}
}

func cliDDH() {
	for {
		fmt.Print("Enter the first vector <x> as comma-separated integers (e.g. <5,128,1,48,3>): ")
		var xInput string
		n, err := fmt.Scanln(&xInput)
		if err != nil || n == 0 {
			fmt.Printf("Error reading input, please try again (%s)\n", err)
			continue
		}

		// Parse the input for x
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

		// Parse the input for y
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
		ddh, err := simple.NewDDH(len(vecX), ModLen, new(big.Int).SetUint64(Bound))
		if err != nil {
			fmt.Printf("Failed to instantiate DDH: %s\n", err)
			continue
		}

		msk, mpk, err := ddh.GenerateMasterKeys()
		if err != nil {
			fmt.Printf("Failed to generate keys: %s\n", err)
			continue
		}

		fmt.Printf("-----------------\n")
		PrintParams(ddh.Params)
		fmt.Printf("-----------------\n")

		// Encrypt the first vector
		c, err := ddh.Encrypt(vecX, mpk)
		if err != nil {
			fmt.Printf("Failed to encrypt vector: %s\n", err)
			continue
		}
		fmt.Printf("Encrypted vector: [%s ]\n", c)

		// Derive the functional encryption key
		feKey, err := ddh.DeriveKey(msk, vecY)
		if err != nil {
			fmt.Printf("Failed to derive functional encryption key: %s\n", err)
			continue
		}
		fmt.Printf("Functional encryption key: %s\n", feKey)

		// Decrypt the encrypted vector with the functional key
		fDec, err := ddh.Decrypt(c, feKey, vecY)
		if err != nil {
			fmt.Printf("Failed to decrypt: %s\n", err)
			continue
		}
		fmt.Printf("Decrypted inner product: %s\n", fDec)

		// Calculate the inner product to verify the decryption
		innerProd := big.NewInt(0)
		for i := range vecX {
			innerProd.Add(innerProd, new(big.Int).Mul(vecX[i], vecY[i]))
		}

		if innerProd.Cmp(fDec) == 0 {
			fmt.Printf("Inner product check 🆗: %s\n", innerProd)
		} else {
			fmt.Printf("Inner product check failed: %d != %d\n", innerProd, fDec)
		}
		break
	}
}

func cliMultiDDH() {
	for {
		fmt.Printf("Enter the number of encryptors: ")
		var numClients int
		n, err := fmt.Scanln(&numClients)
		if err != nil || n == 0 {
			fmt.Printf("Error reading input, please try again (%s)\n", err)
			continue
		}

		fmt.Printf("Enter the length of vectors: ")
		var vecLen int
		n, err = fmt.Scanln(&vecLen)
		if err != nil || n == 0 {
			fmt.Printf("Error reading input, please try again (%s)\n", err)
			continue
		}

		ddh, err := simple.NewDDHMulti(numClients, vecLen, ModLen, new(big.Int).SetUint64(Bound))
		if err != nil {
			fmt.Printf("Failed to instantiate MultiDDH: %s\n", err)
			continue
		}

		mpk, msk, err := ddh.GenerateMasterKeys()
		if err != nil {
			fmt.Printf("Failed to generate keys: %s\n", err)
			continue
		}

		fmt.Printf("-----------------\n")
		PrintParams(ddh.Params)
		fmt.Printf("-----------------\n")

		clients := make([]*simple.DDHMultiClient, numClients)
		for i := range clients {
			clients[i] = simple.NewDDHMultiClient(ddh.Params)
		}

		var xVecs []data.Vector
		ciphers := make([]data.Vector, numClients)
		for i := range clients {
			fmt.Printf("(%d/%d) Enter the vector <x> as comma-separated integers: ", i+1, numClients)

			var xInput string
			n, err = fmt.Scanln(&xInput)
			if err != nil || n == 0 {
				fmt.Printf("Error reading input, please try again (%s)\n", err)
				continue
			}

			// Parse the input for x
			vecX, err := VecFromStr(xInput)
			if err != nil {
				fmt.Printf("Error parsing input: %s\n", err)
				continue
			}
			xVecs = append(xVecs, vecX)

			// Encrypt the vector with this client's OTP key
			c, err := clients[i].Encrypt(vecX, mpk[i], msk.OtpKey[i])
			if err != nil {
				fmt.Printf("Failed to encrypt vector: %s\n", err)
				continue
			}
			ciphers[i] = c
		}
		fmt.Println("All client inputs encrypted.")

		// Ask for y and derive the FE-key
		fmt.Printf("Enter the vector <y> as comma-separated integers: ")
		var yInput string
		n, err = fmt.Scanln(&yInput)
		if err != nil || n == 0 {
			fmt.Printf("Error reading input, please try again (%s)\n", err)
			continue
		}

		// Parse the input for y
		vecY, err := VecFromStr(yInput)
		if err != nil {
			fmt.Printf("Error parsing input: %s\n", err)
			continue
		}
		if len(vecY) < 2 {
			fmt.Println("Vector should have at least 2 elements.")
			continue
		}

		// Repeat Y across matrix
		vecs := make([]data.Vector, numClients)
		for i := range vecs {
			vecs[i] = vecY
		}
		matY, err := data.NewMatrix(vecs)
		if err != nil {
			fmt.Printf("Error creating matrix: %s\n", err)
			continue
		}

		feKey, err := ddh.DeriveKey(msk, matY)
		if err != nil {
			fmt.Printf("Failed to derive functional encryption key: %s\n", err)
			continue
		}

		// Decrypt the encrypted vectors with the functional key
		fDec, err := ddh.Decrypt(ciphers, feKey, matY)
		if err != nil {
			fmt.Printf("Failed to decrypt: %s\n", err)
			continue
		}

		// Calculate the inner product to verify the decryption
		// XXX: does not work
		innerProd := big.NewInt(0)
		for i := range numClients {
			fmt.Println(i)
			for j := range vecY {
				innerProd.Add(innerProd, new(big.Int).Mul(xVecs[i][j], vecY[j]))
			}
		}

		if innerProd.Cmp(fDec) == 0 {
			fmt.Printf("Inner product check 🆗: %s\n", innerProd)
		} else {
			fmt.Printf("Inner product check failed: %d != %d\n", innerProd, fDec)
		}
		break
	}
}
