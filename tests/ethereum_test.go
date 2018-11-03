package tests

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/najimmy/go-simplechain/common"
	"github.com/najimmy/go-simplechain/core"
	"github.com/najimmy/go-simplechain/rlp"
	"github.com/stretchr/testify/assert"
)

func TestRlp(t *testing.T) {
	//https://godoc.org/github.com/ethereum/go-ethereum/rlp#example-Encoder
	header := core.Header{ParentHash: common.Hash{0x01, 0x02, 0x03}, Time: big.NewInt(1540854071)}
	encodedBytes, _ := rlp.EncodeToBytes(header)
	//fmt.Printf("Encoded value value: %#v\n", encodedBytes)

	var header2 core.Header
	rlp.Decode(bytes.NewReader(encodedBytes), &header2)
	//fmt.Printf("Decoded value: %#v\n", header2)
	assert.Equal(t, header.ParentHash, header2.ParentHash, "Test ParentHash")
	assert.Equal(t, header.Time, header2.Time, "Test Time")

	header2 = core.Header{}
	rlp.NewStream(bytes.NewReader(encodedBytes), 0).Decode(&header2)
	// s:=rlp.NewStream(bytes.NewReader(encodedBytes), 0)
	// if _, err := s.List(); err != nil {
	// 	fmt.Printf("List error: %v\n", err)
	// 	return
	// }
	// s.Decode(&header2)
	assert.Equal(t, header.ParentHash, header2.ParentHash, "Test ParentHash")
	assert.Equal(t, header.Time, header2.Time, "Test Time")

	s := rlp.NewStream(bytes.NewReader(encodedBytes), 0)
	kind, size, _ := s.Kind()
	fmt.Printf("Kind: %v size:%d\n", kind, size)
	if _, err := s.List(); err != nil {
		fmt.Printf("List error: %v\n", err)
		return
	}
	kind, size, _ = s.Kind()
	fmt.Printf("Kind: %v size:%d\n", kind, size)
	fmt.Println(s.Bytes())
	kind, size, _ = s.Kind()
	fmt.Printf("Kind: %v size:%d\n", kind, size)
	fmt.Println(s.Bytes())
	kind, size, _ = s.Kind()
	fmt.Printf("Kind: %v size:%d\n", kind, size)
	fmt.Println(s.Uint())
	kind, size, _ = s.Kind()
	fmt.Printf("Kind: %v size:%d\n", kind, size)
	fmt.Println(s.Uint())
	if err := s.ListEnd(); err != nil {
		fmt.Printf("ListEnd error: %v\n", err)
	}
}
