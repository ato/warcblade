package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
)

var warcVersionPattern = regexp.MustCompile(`WARC/1\.[0-9]+`)

type WARCRecord struct {
	VersionMinor int
	Header       textproto.MIMEHeader
	reader       *bufio.Reader
	remaining    int64
	gzip         *gzip.Reader
}

func (record *WARCRecord) Read(p []byte) (int, error) {
	if record.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > record.remaining {
		p = p[0:record.remaining]
	}
	n, err := record.reader.Read(p)
	record.remaining -= int64(n)
	return n, err
}

// Advances to the end of the record and reads the record trailer.
func (record *WARCRecord) Close() error {
	// Read any remaining bytes
	for record.remaining > 0 {
		n := 1<<(strconv.IntSize-1) - 1
		if record.remaining < int64(n) {
			n = int(record.remaining)
		}
		n, err := record.reader.Discard(n)
		record.remaining -= int64(n)
		if err != nil {
			return err
		}
	}

	// Read the trailer
	trailer := make([]byte, 4)
	n, err := io.ReadFull(record.reader, trailer)
	if err != nil {
		return err
	}
	if n < 4 || !bytes.Equal(trailer, []byte("\r\n\r\n")) {
		return textproto.ProtocolError("Invalid record trailer")
	}

	// Ensure we fully consumed the gzip member
	if record.gzip != nil {
		tmp := make([]byte, 1)
		_, err = record.gzip.Read(tmp)
		if err != io.EOF {
			return textproto.ProtocolError("Gzip member is longer than WARC record")
		}
		record.gzip.Close()
	}

	return nil
}

// Reads a (possibly gzip-compressed) WARC record
// record.Close must be called before reading the next record.
func readWARCRecord(r *bufio.Reader) (*WARCRecord, error) {
	// Detect compression
	magic, err := r.Peek(2)
	if err != nil {
		return nil, err
	}
	var gz *gzip.Reader
	if magic[0] == 0x1f && magic[1] == 0x8b { // gzip
		gz, err = gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		gz.Multistream(false) // stop at the end of the current member
		r = bufio.NewReader(gz)
	}
	tp := textproto.NewReader(r)

	// Read version line
	version, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(version, "WARC/1.") {
		return nil, textproto.ProtocolError(fmt.Sprintf("Invalid WARC %x %x", version[0], version[1]))
	}
	versionMinor, err := strconv.ParseUint(version[len("WARC/1."):], 10, 0)
	if err != nil {
		return nil, textproto.ProtocolError("Invalid WARC version line")
	}

	// Read header fields
	header, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}

	// Determine length of the content block
	lenStr := header.Get("Content-Length")
	if lenStr == "" {
		return nil, textproto.ProtocolError("Missing Content-Length")
	}
	len, err := strconv.ParseInt(lenStr, 10, 0)
	if err != nil || len < 0 {
		return nil, textproto.ProtocolError("Invalid Content-Length")
	}

	return &WARCRecord{int(versionMinor), header, r, len, gz}, nil
}
