package main

import (
	"bufio"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"
)

const CDXTIME = "20060102150405"

func cmdCdx(args []string) {
	err := cdx(os.Stdin)
	if err != nil {
		panic(err)
	}
}

type countingReader struct {
	r io.Reader
	pos int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.pos += int64(n)
	return n, err
}

func cdx(file *os.File) error {
	filename := file.Name()
	cr := countingReader{file, 0}
	br := bufio.NewReader(&cr)

	for {
		// Parse the record header
		start := cr.pos - int64(br.Buffered())
		record, err := readWARCRecord(br)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		var payloadType string
		var status int
		url := record.Header.Get("Warc-Target-Uri")
		date, err := time.Parse(time.RFC3339, record.Header.Get("Warc-Date"))
		if err != nil {
			return err
		}
		digest := strings.TrimPrefix(record.Header.Get("Warc-Payload-Digest"), "sha1:")

		switch record.Header.Get("Warc-Type") {
		case "":
			return textproto.ProtocolError("Missing WARC-Type header")
		case "response":
			if t, _, err := mime.ParseMediaType(record.Header.Get("Content-Type")); err != nil || t != "application/http" {
				err = record.Close()
				if err != nil {
					return err
				}
				continue
			}
			resp, err := http.ReadResponse(bufio.NewReader(record), nil)
			if err == nil {
				payloadType = resp.Header.Get("Content-Type")
				status = resp.StatusCode
			}
		case "resource":
			payloadType = record.Header.Get("Content-Type")
			status = 200
		default:
			err = record.Close()
			if err != nil {
				return err
			}
			continue
		}

		err = record.Close()
		if err != nil {
			return err
		}

		// Unsupported for now
		redirect := "-"
		robots := "-"

		// Print the CDX line
		payloadType, _, err = mime.ParseMediaType(payloadType)
		if err != nil {
			payloadType = "-"
		}
		end := cr.pos - int64(br.Buffered())
		rawLength := end - start
		fmt.Printf("- %s %s %s %d %s %s %s %d %d %s\n", date.Format(CDXTIME), url, payloadType, status, digest,
			redirect, robots, rawLength, start, filename)
	}
}
