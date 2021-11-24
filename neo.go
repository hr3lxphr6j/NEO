package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path"
	"runtime"
)

const (
	VersionV1 uint8 = 1

	FlagVersion = 0b00001111

	XorEnc uint8 = 1
)

var (
	NeoMagicNumber = []byte{0xFF, 0x4E, 0x45, 0x4F}

	ErrCRCCheckFailed      = errors.New("crc check failed")
	ErrNotNEOHeader        = errors.New("not a NEO header")
	ErrBadVersion          = errors.New("bad version")
	ErrUnknownCryptoMethod = errors.New("unknown crypto method")
)

type NeoHeader struct {
	Version                   uint8
	OriginalHeaderEncMethod   uint8
	OriginalHeader            []byte
	OriginalFilenameEncMethod uint8
	OriginalFilename          string
	Crc32                     uint32
}

func encodeVUint(u uint) []byte {
	buf := new(bytes.Buffer)
	for i := 0; i < int(u)/0xFF; i++ {
		buf.WriteByte(0xFF)
	}
	buf.WriteByte(byte(u % 0xFF))
	return buf.Bytes()
}

func decodeVUint(p []byte) (res uint, surplus []byte) {
	for idx, v := range p {
		if v == 0xFF {
			res += 0xFF
			continue
		}
		res += uint(v)
		surplus = p[idx+1:]
		break
	}
	return
}

func writeContentWithXorEnc(buf *bytes.Buffer, content, key []byte) {
	buf.WriteByte(XorEnc)
	buf.Write(encodeVUint(uint(len(key))))
	buf.Write(key)
	buf.Write(encodeVUint(uint(len(content))))
	dst := make([]byte, len(content))
	NewXorStream(key).XORKeyStream(dst, content)
	buf.Write(dst)
}

func loadContextWithXorEnc(p []byte) (content, surplus []byte) {
	var (
		keyLen, contentLen uint
		key, secContent    []byte
	)
	keyLen, surplus = decodeVUint(p)
	key, surplus = surplus[:keyLen], surplus[keyLen:]
	contentLen, surplus = decodeVUint(surplus)
	secContent, surplus = surplus[:contentLen], surplus[contentLen:]
	content = make([]byte, contentLen)
	NewXorStream(key).XORKeyStream(content, secContent)
	return
}

func (h NeoHeader) Marshall() ([]byte, error) {
	if h.Version != VersionV1 {
		return nil, ErrBadVersion
	}

	buf := new(bytes.Buffer)

	var flag byte = 0
	flag |= h.Version & FlagVersion
	buf.WriteByte(flag)

	// encode originalHeader
	switch h.OriginalHeaderEncMethod {
	case XorEnc:
		key := make([]byte, 4)
		if _, err := rand.Reader.Read(key); err != nil {
			return nil, err
		}
		writeContentWithXorEnc(buf, h.OriginalHeader, key)
	default:
		return nil, ErrUnknownCryptoMethod
	}

	switch h.OriginalFilenameEncMethod {
	case XorEnc:
		key := make([]byte, 4)
		if _, err := rand.Reader.Read(key); err != nil {
			return nil, err
		}
		writeContentWithXorEnc(buf, []byte(h.OriginalFilename), key)
	default:
		return nil, ErrUnknownCryptoMethod
	}

	crc := make([]byte, 4)
	binary.BigEndian.PutUint32(crc, h.Crc32)
	buf.Write(crc)

	contentLenVint := encodeVUint(uint(buf.Len()))
	res := make([]byte, 4+len(contentLenVint)+buf.Len())
	copy(res[:4], NeoMagicNumber)
	copy(res[4:], contentLenVint)
	copy(res[4+len(contentLenVint):], buf.Bytes())
	return res, nil
}

func (h *NeoHeader) UnMarshall(p []byte) error {
	if len(p) <= 4 {
		return ErrNotNEOHeader
	}
	var (
		neoHdrlen uint
		flag      byte = 0
	)
	neoHdrlen, p = decodeVUint(p[4:])
	if uint(len(p)) != neoHdrlen {
		panic("len not equal")
	}
	flag, p = p[0], p[1:]
	h.Version = flag & FlagVersion
	if h.Version != VersionV1 {
		return ErrBadVersion
	}
	h.OriginalHeaderEncMethod, p = p[0], p[1:]
	switch h.OriginalHeaderEncMethod {
	case XorEnc:
		h.OriginalHeader, p = loadContextWithXorEnc(p)
	default:
		return ErrUnknownCryptoMethod
	}

	h.OriginalFilenameEncMethod, p = p[0], p[1:]
	switch h.OriginalFilenameEncMethod {
	case XorEnc:
		var filename []byte
		filename, p = loadContextWithXorEnc(p)
		h.OriginalFilename = string(filename)
	default:
		return ErrUnknownCryptoMethod
	}

	var crc32 []byte
	crc32, p = p[:4], p[4:]
	h.Crc32 = binary.BigEndian.Uint32(crc32)

	return nil
}

type NeoWriter struct {
	originHdrLen    int
	hdr             *NeoHeader
	w               io.Writer
	buf             *bytes.Buffer
	isNewHdrWritten bool
}

func NewNeoWriter(w io.Writer, hdrLen int, filename string, crc32 uint32) io.Writer {
	return &NeoWriter{
		originHdrLen: hdrLen,
		hdr: &NeoHeader{
			Version:                   VersionV1,
			OriginalHeaderEncMethod:   XorEnc,
			OriginalHeader:            nil,
			OriginalFilenameEncMethod: XorEnc,
			OriginalFilename:          filename,
			Crc32:                     crc32,
		},
		w:               w,
		buf:             new(bytes.Buffer),
		isNewHdrWritten: false,
	}
}

func (w *NeoWriter) Write(p []byte) (n int, err error) {
	if w.isNewHdrWritten {
		return w.w.Write(p)
	}
	if w.buf.Len() < w.originHdrLen {
		if len(p) <= w.originHdrLen {
			return w.buf.Write(p)
		}
		if n, err := w.buf.Write(p[:w.originHdrLen]); err != nil {
			return n, err
		}
	}
	// got enough bytes
	w.hdr.OriginalHeader = w.buf.Bytes()
	hdr, err := w.hdr.Marshall()
	if err != nil {
		return
	}
	if _, err := w.w.Write(hdr); err != nil {
		return 0, err
	}
	w.isNewHdrWritten = true
	n, err = w.w.Write(p[w.originHdrLen:])
	n += w.originHdrLen
	return
}

type NeoReader struct {
	n         int
	rd        *bufio.Reader
	NeoHeader *NeoHeader
	buf       []byte
}

func NewNeoReader(r io.Reader) *NeoReader {
	return &NeoReader{
		rd:  bufio.NewReader(r),
		buf: make([]byte, 1024),
	}
}

func (r *NeoReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	if r.NeoHeader != nil {
		if r.n < len(r.NeoHeader.OriginalHeader) {
			n = copy(p, r.NeoHeader.OriginalHeader[r.n:])
			r.n += n
			n_, err_ := r.Read(p[r.n:])
			return n_ + n, err_
		}
		return r.rd.Read(p)
	}
	if _, err := r.rd.Read(r.buf[:len(NeoMagicNumber)]); err != nil {
		return 0, nil
	}
	if !bytes.Equal(r.buf[:len(NeoMagicNumber)], NeoMagicNumber) {
		return 0, ErrNotNEOHeader
	}
	n_ := 0
	hdrLen := 0
	for {
		v, err := r.rd.ReadByte()
		if err != nil {
			return 0, err
		}
		hdrLen += int(v)
		n_++
		if v != 0xFF {
			break
		}
	}
	var hdr []byte
	if len(r.buf) >= len(NeoMagicNumber)+n_+hdrLen {
		hdr = r.buf[:len(NeoMagicNumber)+n_+hdrLen]
	} else {
		hdr = make([]byte, len(NeoMagicNumber)+n+hdrLen)
	}
	copy(hdr, NeoMagicNumber)
	copy(hdr[len(NeoMagicNumber):], encodeVUint(uint(hdrLen)))
	if _, err := r.rd.Read(hdr[len(NeoMagicNumber)+n_:]); err != nil {
		return 0, err
	}
	r.NeoHeader = new(NeoHeader)
	if err := r.NeoHeader.UnMarshall(hdr); err != nil {
		return 0, nil
	}
	return r.Read(p)
}

func crc32ofFile(filename string) (uint32, error) {
	h := crc32.NewIEEE()
	fromFd, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer fromFd.Close()
	if _, err := io.Copy(h, fromFd); err != nil {
		return 0, err
	}
	return h.Sum32(), nil
}

func decodeFile(filename string) {
	fromFd, err := os.Open(filename)
	if err != nil {
		log.Printf("无法打开文件：%s，错误：%v", filename, err)
		return
	}
	success := false
	toFilename := filename + ".decoding"
	toFd, err := os.OpenFile(toFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		log.Printf("无法打开文件：%s，错误：%v", filename, err)
		return
	}
	defer func() {
		toFd.Close()
		if !success {
			os.Remove(toFilename)
		}
	}()
	h := crc32.NewIEEE()
	neoRd := NewNeoReader(fromFd)
	if _, err := io.Copy(toFd, io.TeeReader(neoRd, h)); err != nil {
		log.Printf("写入文件：%s，错误：%v", toFilename, err)
		return
	}
	toFd.Close()
	if crc32_ := h.Sum32(); crc32_ != neoRd.NeoHeader.Crc32 {
		log.Printf("文件：%s CRC校验失败 %d != %d, 文件损毁", filename, neoRd.NeoHeader.Crc32, crc32_)
		return
	}
	success = true
	if err := os.Rename(toFilename, path.Join(path.Dir(filename), neoRd.NeoHeader.OriginalFilename)); err != nil {
		log.Printf("重命名文件 %s 失败", filename)
	}
}

func encodeFile(filename string) {
	crc32_, err := crc32ofFile(filename)
	if err != nil {
		log.Printf("无法计算文件：%s CRC32，错误：%v", filename, err)
		return
	}
	fromFd, err := os.Open(filename)
	if err != nil {
		log.Printf("无法打开文件：%s，错误：%v", filename, err)
		return
	}
	defer fromFd.Close()
	toFilename := path.Join(path.Dir(filename), RandStringRunes(8)+".neo")
	toFd, err := os.OpenFile(toFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		log.Printf("无法打开文件：%s，错误：%v", filename, err)
		return
	}
	defer toFd.Close()
	w := NewNeoWriter(toFd, 8, path.Base(filename), crc32_)
	if _, err := io.Copy(w, fromFd); err != nil {
		log.Printf("写入文件：%s，错误：%v", toFilename, err)
		return
	}
}

func IsNeoFile(filename string) (bool, error) {
	fromFd, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer fromFd.Close()
	magicNum := make([]byte, len(NeoMagicNumber))
	if _, err := fromFd.Read(magicNum); err != nil {
		return false, err
	}
	return bytes.Equal(magicNum, NeoMagicNumber), nil
}

func parseFile(filename string) {
	isNeoFile, err := IsNeoFile(filename)
	if err != nil {
		log.Printf("判断文件：%s 类型失败，错误：%v", filename, err)
		return
	}
	if isNeoFile {
		decodeFile(filename)
	} else {
		encodeFile(filename)
	}
}

func main() {
	for _, item := range os.Args[1:] {
		fInfo, err := os.Stat(item)
		switch err {
		case nil:
		case os.ErrNotExist:
			log.Printf("文件：%s 不存在", item)
			continue
		default:
			log.Printf("获取文件：%s 信息失败，错误：%v", item, err)
			continue
		}
		if !fInfo.Mode().IsRegular() {
			log.Printf("%s 不是一个普通文件，跳过", item)
			continue
		}
		parseFile(item)
	}

	if runtime.GOOS == "windows" {
		fmt.Println("Press the Enter Key to stop anytime")
		fmt.Scanln()
	}
}
