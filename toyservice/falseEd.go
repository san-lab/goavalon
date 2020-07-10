package toyservice

import (
	"github.com/agl/ed25519/edwards25519"
	"crypto/sha256"
	"crypto/rand"
	"fmt"
	"math/big"
	"bytes"
)



//Verification
//x := new(big.Int)
//x.SetString(BankEd, 10)
//bankEdPriv := Tli(x)
//ss2 := EdwardsScalarAddMult(bankEdPriv, ephEdpublic, Zero)
//plaintext2 := hex.EncodeToString(ss2[:])
//fmt.Println("a",plaintext)
//fmt.Println("b", plaintext2)



func sSign(privateKey *[32]byte, message []byte) []byte {
	r := new([32]byte)
	rand.Reader.Read(r[:])
	r[31] &=127 //This should work instead of actual MOD

	R := EdwardsScalarMultB(r)
	fmt.Println("R:", R)
	h := sha256.New()
	h.Write(R[:])
	h.Write(message)
	mdt := h.Sum(nil)
	md_long := new ([64]byte)
	copy(md_long[:], mdt)
	md := new([32]byte)
	edwards25519.ScReduce(md, md_long)
	s := new([32]byte)
	edwards25519.ScMulAdd(s, md, privateKey, r)
	sign := make([]byte, 64)
	copy(sign[:32], R[:])
	copy(sign[32:], s[:])
	return sign
}
//   where l = 2^252 + 27742317777372353535851937790883648493


func sVerify(pubkey *[32]byte, signature, message []byte) (bool, error) {

	if len(signature) != 64 {
		return false, fmt.Errorf("Wrong signature length: %v", len(signature))
	}
	l := big.NewInt(0)
	l.SetString(Ed25519OrderString, 10)

	R := new([32]byte)
	copy(R[:], signature[:32])

	s := new([32]byte)
	copy(s[:], signature[32:])

	h := sha256.New()
	h.Write(R[:])
	h.Write(message)
	mdt := h.Sum(nil)


	md := new ([32]byte)
	copy(md[:], mdt)

	hneg := big.NewInt(0)
	hneg.Sub(l,Fli(md))
	hneg.Mod(hneg,l)
	mdneglitend := Tli(hneg)

	X := EdwardsScalarAddMult(mdneglitend,pubkey, s)
	return bytes.Equal(R[:], X[:]),  nil
}

