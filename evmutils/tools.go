/*
 * Copyright 2020 The SealEVM Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package evmutils

import (
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

const (
	hashLength    = 32
	AddressLength = 20
)

type Address [AddressLength]byte

func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

var (
	BlankHash = make([]byte, hashLength, hashLength)
	ZeroHash  = Keccak256(nil)
)

// EVMIntToHashBytes returns the absolute value of x as a big-endian fixed length byte slice.
func EVMIntToHashBytes(i *Int) [hashLength]byte {
	iBytes := i.Bytes()
	iLen := len(iBytes)

	var hash [hashLength]byte
	if iLen > hashLength {
		copy(hash[:], iBytes[iLen-hashLength:])
	} else {
		copy(hash[hashLength-iLen:], iBytes)
	}

	return hash
}

// EthHashBytesToEVMInt EVMIntToHashBytes reverse
func EthHashBytesToEVMInt(hash [hashLength]byte) (*Int, error) {
	return HashBytesToEVMInt(hash[:])
}

// HashBytesToEVMInt byte to bigInt
func HashBytesToEVMInt(hash []byte) (*Int, error) {
	i := New(0)
	i.SetBytes(hash[:])
	return i, nil
}

// BytesDataToEVMIntHash fixed length bytes
func BytesDataToEVMIntHash(data []byte) *Int {
	var hashBytes []byte
	srcLen := len(data)
	if srcLen < hashLength {
		hashBytes = LeftPaddingSlice(data, hashLength)
	} else {
		hashBytes = data[:hashLength]
	}

	i := New(0)
	i.SetBytes(hashBytes)

	return i
}

func GetDataFrom(src []byte, offset uint64, size uint64) []byte {
	ret := make([]byte, size, size)
	dLen := uint64(len(src))
	if dLen < offset {
		return ret
	}

	end := offset + size
	if dLen < end {
		end = dLen
	}

	copy(ret, src[offset:end])
	return ret
}

func LeftPaddingSlice(src []byte, toSize int) []byte {
	sLen := len(src)
	if toSize <= sLen {
		return src
	}

	ret := make([]byte, toSize, toSize)
	copy(ret[toSize-sLen:], src)

	return ret
}

func RightPaddingSlice(src []byte, toSize int) []byte {
	sLen := len(src)
	if toSize <= sLen {
		return src
	}

	ret := make([]byte, toSize, toSize)
	copy(ret, src)

	return ret
}

func Keccak256(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	return hasher.Sum(nil)
}

// LeftPadBytes zero-pads slice to the left up to length l.
func LeftPadBytes(slice []byte, l int) []byte {
	if l <= len(slice) {
		return slice
	}

	padded := make([]byte, l)
	copy(padded[l-len(slice):], slice)

	return padded
}

// MakeAddressFromHex any hex str make a evm.Int
func MakeAddressFromHex(str string) (*Int, error) {
	data, err := FromHex(str)
	if err != nil {
		return nil, err
	}
	return MakeAddress(data), nil
}

// MakeAddressFromString any str make a evm.Int
func MakeAddressFromString(str string) (*Int, error) {
	return MakeAddress([]byte(str)), nil
}

// MakeAddress any byte make a evm.Int
func MakeAddress(data []byte) *Int {
	address := Keccak256(data)
	addr := hex.EncodeToString(address)[24:]
	return FromHexString(addr)
}

// BytesToAddress any byte set to a evm address
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

// StringToAddress any string make a evm address
func StringToAddress(s string) (Address, error) {
	addrInt, err := MakeAddressFromString(s)
	if err != nil {
		var a Address
		return a, err
	}
	return BigToAddress(addrInt), nil
}

// HexToAddress any hex make a evm address
func HexToAddress(s string) (Address, error) {
	addrInt, err := MakeAddressFromHex(s)
	if err != nil {
		var a Address
		return a, err
	}
	return BigToAddress(addrInt), nil
}

// BigToAddress math.bigInt to evm address
func BigToAddress(b *Int) Address {
	return BytesToAddress(b.Bytes())
}

func FromHex(s string) ([]byte, error) {
	if Has0xPrefix(s) {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func Has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}
