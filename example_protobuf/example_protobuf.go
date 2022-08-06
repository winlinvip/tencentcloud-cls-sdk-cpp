package main

import (
	"encoding/hex"
	"fmt"
	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/encoding/protowire"
	"math/bits"
)

type MyUser struct {
	ID   int64  `protobuf:"zigzag64,1"`
	Age  uint32 `protobuf:"varint,2"`
	Name string `protobuf:"bytes,3"`
}

func (v *MyUser) Reset() {
	*v = MyUser{}
}

func (v *MyUser) String() string {
	return "Hello"
}

func (v *MyUser) ProtoMessage() {
}

func main() {
	if true {
		n := bits.Len64(0)
		nn := int(9*uint32(n)+64) / 64
		fmt.Println(fmt.Sprintf("protowire.SizeVarint(0)=%v, nn=%v", protowire.SizeVarint(0)), nn)
	}

	if true {
		fmt.Println(fmt.Sprintf("protowire.SizeVarint(1)=%v", protowire.SizeVarint(1)))

		b := proto.NewBuffer(nil)
		_ = b.EncodeVarint(1)
		fmt.Println("Hex of b.EncodeVarint(1):")
		fmt.Println(hex.Dump(b.Bytes()))
	}
	if true {
		fmt.Println(fmt.Sprintf("protowire.SizeVarint(1)=%v", protowire.SizeVarint(1)))

		b := proto.NewBuffer(nil)
		_ = b.EncodeZigzag64(1)
		fmt.Println("Hex of b.EncodeZigzag64(1):")
		fmt.Println(hex.Dump(b.Bytes()))
	}

	// If use varint sint64 to encode -1(0xffffffffffffffff), it will be 10bytes.
	if true {
		fmt.Println(fmt.Sprintf("protowire.SizeVarint(0xffffffffffffffff)=%v", protowire.SizeVarint(0xffffffffffffffff)))

		b := proto.NewBuffer(nil)
		_ = b.EncodeVarint(0xffffffffffffffff)
		fmt.Println("Hex of b.EncodeVarint(0xffffffffffffffff):")
		fmt.Println(hex.Dump(b.Bytes()))
	}

	// So we use zigzag to encode -1(0xffffffffffffffff) as 1
	if true {
		v := protowire.EncodeZigZag(-1)
		fmt.Println(fmt.Sprintf("protowire.EncodeZigZag(-1)=%v", v))
		fmt.Println(fmt.Sprintf("protowire.SizeVarint(-1)=%v", protowire.SizeVarint(v)))

		b := proto.NewBuffer(nil)
		_ = b.EncodeZigzag64(0xffffffffffffffff)
		fmt.Println("Hex of b.EncodeZigzag64(-1):")
		fmt.Println(hex.Dump(b.Bytes()))
	}

	// Encode a struct with int32, sint64 and string.
	if true {
		v := &MyUser{
			-1, 1, "SRS",
		}

		b := proto.NewBuffer(nil)
		_ = b.Marshal(v)
		fmt.Println("Hex of b.Marshal(struct):")
		fmt.Println(hex.Dump(b.Bytes()))
	}

	if true {
		fmt.Println(fmt.Sprintf("protowire.SizeBytes(1)=%v", protowire.SizeBytes(1)))

		b := proto.NewBuffer(nil)
		_ = b.EncodeStringBytes("HI")
		fmt.Println("Hex of b.EncodeStringBytes(HI):")
		fmt.Println(hex.Dump(b.Bytes()))
	}
}
