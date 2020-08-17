package cfbypass

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"
)

var (
	dialer = &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 15 * time.Second,
		DualStack: true,
	}

	directTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient = &http.Client{
		Transport: directTransport,
		Timeout:   15 * time.Second,
	}
)

func init() {
	LogEnabled = true
	LogBodyEnabled = true
}

func TestSolveChallenge1(t *testing.T) {
	host := "itorrents.org"
	body, _ := ioutil.ReadFile("tests/test1.html")
	answerTarget := "17.3509146264"

	answer, _, err := solveChallenge(body, host)
	if err != nil {
		t.Errorf("Error from solveChallenge: %s", err)
	} else if answer != answerTarget {
		t.Errorf("Answer does not match. Got: %s, need: %s", answer, answerTarget)
	}
}

func TestSolveChallenge2(t *testing.T) {
	host := "www.haypost.am"
	body, _ := ioutil.ReadFile("tests/test2.html")
	answerTarget := "16.7026105073"

	answer, _, err := solveChallenge(body, host)
	if err != nil {
		t.Errorf("Error from solveChallenge: %s", err)
	} else if answer != answerTarget {
		t.Errorf("Answer does not match. Got: %s, need: %s", answer, answerTarget)
	}
}

func TestGetRequest1(t *testing.T) {
	buffer := new(bytes.Buffer)
	req, err := http.NewRequest("GET", "https://itorrents.org/torrent/B84A56A5254E51DDADBF4014A61419BDDE68A687.torrent?title=Avengers-Endgame-2019-BDRip-1080p-seleZen", buffer)
	if err != nil {
		t.Errorf("Cannot make request: %s", err)
	}

	// Set custom headers
	req.Header.Add("User-Agent", `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.27 Safari/537.36`)

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Errorf("Execution error: %s", err)
	}

	if !IsCloudFlared(resp) {
		t.Error("Response should be Cloudflared for a test")
	}

	if _, err := RunClient(resp, httpClient); err != nil {
		t.Errorf("Error from RunClient: %s", err)
	}
}

func TestGetRequest2(t *testing.T) {
	buffer := new(bytes.Buffer)
	req, err := http.NewRequest("GET", "https://www.haypost.am/en/track-and-trace/", buffer)
	if err != nil {
		t.Errorf("Cannot make request: %s", err)
	}

	// Set custom headers
	req.Header.Add("User-Agent", `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.27 Safari/537.36`)

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Errorf("Execution error: %s", err)
	}

	if !IsCloudFlared(resp) {
		t.Error("Response should be Cloudflared for a test")
	}

	if _, err := RunClient(resp, httpClient); err != nil {
		t.Errorf("Error from RunClient: %s", err)
	}
}
