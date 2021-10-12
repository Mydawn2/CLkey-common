/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/Mydawn2/CLkey-common/crypto"
	"github.com/stretchr/testify/require"
)

var msg = "js"

func TestSM2(t *testing.T) {
	h := sha256.Sum256([]byte(msg))
	priv, err := New(crypto.SM2, []byte("myda2wn"))
	require.Nil(t, err)

	privDER, err := priv.Bytes()
	require.Nil(t, err)

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privDER,
	}

	err = pem.Encode(os.Stdout, block)
	require.Nil(t, err)

	buf, err := priv.String()
	require.Nil(t, err)
	fmt.Println(buf)

	sign, err := priv.Sign(h[:])
	require.Nil(t, err)
	require.NotEqual(t, nil, sign)
	pub := priv.PublicKey()
	buf, err = pub.String()
	require.Nil(t, err)
	fmt.Println(buf)

	b, err := pub.Verify(h[:], sign)
	require.Nil(t, err)
	require.True(t, b)
}

func TestCLkey(t *testing.T) {
	h := sha256.Sum256([]byte(msg))
	priv, err := New(crypto.CLkey, []byte("myda2wn"))
	require.Nil(t, err)

	privDER, err := priv.Bytes()
	require.Nil(t, err)

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privDER,
	}

	err = pem.Encode(os.Stdout, block)
	require.Nil(t, err)

	buf, err := priv.String()
	require.Nil(t, err)
	fmt.Println(buf)

	sign, err := priv.Sign(h[:])
	require.Nil(t, err)
	require.NotEqual(t, nil, sign)
	pub := priv.PublicKey()
	buf, err = pub.String()
	require.Nil(t, err)
	fmt.Println(buf)

	b, err := pub.Verify(h[:], sign)
	require.Nil(t, err)
	require.True(t, b)
}

func TestP256(t *testing.T) {
	h := sha256.Sum256([]byte(msg))
	priv, err := New(crypto.ECC_NISTP256, []byte("myda2wn"))
	require.Nil(t, err)

	buf, err := priv.String()
	require.Nil(t, err)
	fmt.Println(buf)

	sign, err := priv.Sign(h[:])
	require.Nil(t, err)
	require.NotEqual(t, nil, sign)

	pub := priv.PublicKey()
	buf, err = pub.String()
	require.Nil(t, err)
	fmt.Println(buf)

	b, err := pub.Verify(h[:], sign)
	require.Nil(t, err)
	require.True(t, b)
}

func TestSecp256k1(t *testing.T) {
	h := sha256.Sum256([]byte(msg))
	priv, err := New(crypto.ECC_Secp256k1, []byte("myda2wn"))
	require.Nil(t, err)

	buf, err := priv.String()
	require.Nil(t, err)
	fmt.Println(buf)

	sign, err := priv.Sign(h[:])
	require.Nil(t, err)
	require.NotEqual(t, nil, sign)

	pub := priv.PublicKey()
	buf, err = pub.String()
	require.Nil(t, err)
	fmt.Println(buf)

	b, err := pub.Verify(h[:], sign)
	require.Nil(t, err)
	require.True(t, b)
}
