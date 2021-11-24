package main

import (
	"bytes"
	"crypto/rand"
	"hash/crc32"
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestVint(t *testing.T) {
	for i := 0; i <= 1<<16; i++ {
		v := encodeVUint(uint(i))
		ui, p := decodeVUint(v)
		if len(p) != 0 {
			t.Fatal("len(p) != 0")
		}
		if ui != uint(i) {
			t.Fatalf("except %d, but %d", i, ui)
		}
	}
}

func TestNeoHeader_Marshall(t *testing.T) {
	hdr := &NeoHeader{
		Version:                   VersionV1,
		OriginalHeaderEncMethod:   XorEnc,
		OriginalHeader:            []byte{0x52, 0x61, 0x71, 0x21, 0x1a, 0x07, 0x01, 0x00},
		OriginalFilenameEncMethod: XorEnc,
		OriginalFilename:          "这是压缩文件❤️.rar",
		Crc32:                     6655,
	}
	b, err := hdr.Marshall()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%x", b)
	hdr_ := new(NeoHeader)
	if err := hdr_.UnMarshall(b); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+#v", hdr_)
}

func TestNewNeoWriter(t *testing.T) {
	testFilename := path.Join(t.TempDir(), "test.bin")
	var crc32_ uint32
	func() {
		fd, err := os.OpenFile(testFilename, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0777)
		if err != nil {
			t.Fatal(err)
		}
		defer fd.Close()
		h := crc32.NewIEEE()
		if _, err := io.CopyN(fd, io.TeeReader(rand.Reader, h), 128); err != nil {
			t.Fatal(err)
		}
		crc32_ = h.Sum32()
	}()
	buf := new(bytes.Buffer)
	func() {
		fd, err := os.Open(testFilename)
		if err != nil {
			t.Fatal(err)
		}
		defer fd.Close()
		w := NewNeoWriter(buf, 32, path.Base(testFilename), crc32_)
		if _, err := io.Copy(w, fd); err != nil {
			t.Fatal(err)
		}
		t.Logf("%x", buf.Bytes())
	}()

	func() {
		rd := NewNeoReader(buf)
		b, err := ioutil.ReadAll(rd)
		if err != nil {
			t.Fatal(err)
		}
		crc32_ := crc32.ChecksumIEEE(b)
		if crc32_ != rd.NeoHeader.Crc32 {
			t.Fatalf("crc check failed, except: %d but: %d", rd.NeoHeader.Crc32, crc32_)
		}
		t.Logf("%#v", rd.NeoHeader)
	}()

}
