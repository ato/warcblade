package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

func cmdGet(args []string) {
	//f, err := os.Create("hello.warc")
	//if err != nil {
	//	panic(err)
	//}
	//defer f.Close()

	err := fetch(args[0], os.Stdout)
	if err != nil {
		panic(err)
	}
}

func fetch(url string, out *os.File) error {
	request_id := uuid()
	date := time.Now().UTC().Format(time.RFC3339)

	// Send the HTTP request
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()


	// Save the response body to a temporary file
	body_file, err := ioutil.TempFile("", "warcblade")
	if err != nil {
		return err
	}
	defer body_file.Close()
	defer os.Remove(body_file.Name())
	hasher := sha1.New()
	body_len, err := io.Copy(body_file, io.TeeReader(resp.Body, hasher))
	if err != nil {
		return err
	}
	_, err = body_file.Seek(0, 0)
	if err != nil {
		return err
	}
	body_sha1 := base32.StdEncoding.EncodeToString(hasher.Sum(nil))

	// Write the request record
	http_request := new(bytes.Buffer)
	resp.Request.Write(http_request)
	_, err = fmt.Fprintf(out, "WARC/1.0\r\n" +
		"WARC-Type: request\r\n" +
		"WARC-Record-ID: <urn:uuid:%s>\r\n" +
		"WARC-Target-URI: %s\r\n" +
		"WARC-Date: %s\r\n" +
		"Content-Type: application/http;msgtype=request\r\n" +
		"Content-Length: %d\r\n" +
		"\r\n%s\r\n\r\n", request_id, url, date, http_request.Len(), http_request)
	if err != nil {
		return err
	}

	// Write the response record
	http_response := new(bytes.Buffer)
	fmt.Fprintf(http_response, "HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
	resp.Header.WriteSubset(http_response, map[string]bool{"Transfer-Encoding": true})
	block_len := int64(http_response.Len()) + 2 + body_len
	_, err = fmt.Fprintf(out, "WARC/1.0\r\n"+
		"WARC-Type: response\r\n"+
		"WARC-Record-ID: <urn:uuid:%s>\r\n"+
		"WARC-Target-URI: %s\r\n"+
		"WARC-Date: %s\r\n" +
		"WARC-Concurrent-To: <urn:uuid:%s>\r\n" +
		"WARC-Payload-Digest: sha1:%s\r\n" +
		"Content-Type: application/http;msgtype=response\r\n" +
		"Content-Length: %d\r\n"+
		"\r\n%s\r\n", uuid(), url, date, request_id, body_sha1, block_len, http_response)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, body_file)
	if err != nil {
		return err
	}

	out.Write([]byte("\r\n\r\n"))

	return nil
}

func uuid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6] & 0x0f | 0x40 // version 4
	b[8] = b[8] & 0xbf | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}