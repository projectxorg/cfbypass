package cfbypass

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	logging "github.com/op/go-logging"
	"github.com/robertkrimen/otto"
)

type callerFunc func(*http.Request) (*http.Response, error)

var (
	log = logging.MustGetLogger("cfbypass")

	// LogEnabled sets logging setting to dump all requests and responses
	LogEnabled = false

	// LogBodyEnabled sets logging response body
	LogBodyEnabled = false

	// Different regexps used all over the way in here
	reForm           = regexp.MustCompile(`(?s)<form.*?id=\"challenge-form\".*?\/form\>`)
	reFormMethod     = regexp.MustCompile(`(?s)method=\"(.*?)\"`)
	reFormAction     = regexp.MustCompile(`(?s)action=\"(.*?)\"`)
	reFormInput      = regexp.MustCompile(`(?s)\<input.*?(?:\/>|\<\/input\>)`)
	reFormInputName  = regexp.MustCompile(`(?s)name=\"(.*?)\"`)
	reFormInputValue = regexp.MustCompile(`(?s)value=\"(.*?)\"`)

	reJavaScript = regexp.MustCompile(`(?s)\<script type\=\"text\/javascript\"\>\n(.*?)\<\/script\>`)
	reChallenge  = regexp.MustCompile(`(?s)setTimeout\(function\(\){\s*(var s,t,o,p.?b,r,e,a,k,i,n,g,f.+?\r?\n[\s\S]+?a\.value\s*=.+?)\r?\n(?:[^{<>]*},\s*(\d{4,}))?`)
	reAValue     = regexp.MustCompile(`(?s)a\.value\s*\=`)

	reReplaceItalics = regexp.MustCompile(`(?s)\(\"\"\)\[\"italics\"\]\(\)`)
)

// RunClient checks http.Client response and solves the CloudFlare challenge if needed.
// Request is re-requested
func RunClient(resp *http.Response, client *http.Client) (*http.Response, error) {
	if !IsCloudFlared(resp) {
		return resp, nil
	}

	caller := func(req *http.Request) (*http.Response, error) {
		return client.Do(req)
	}
	if cfResponse, passed, err := solveCloudFlare(resp, resp.Request, caller); passed && err == nil {
		// resp.Request.Body = ioutil.NopCloser(resp.Request.Body)

		if cfResponse != nil {
			for _, cookie := range cfResponse.Cookies() {
				resp.Request.AddCookie(cookie)
			}
		}

		if respRetry, err := client.Do(resp.Request); err == nil && respRetry != nil {
			if set := cfResponse.Header.Get("Set-Cookie"); set != "" {
				respRetry.Header.Add("Set-Cookie", set)
			}

			return respRetry, nil
		}
	} else if err != nil {
		return nil, err
	}

	return nil, nil
}

// RunProxy checks goproxy response and solves the CloudFlare challenge if needed
func RunProxy(resp *http.Response, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	if !IsCloudFlared(resp) {
		return resp, nil
	}

	caller := func(req *http.Request) (*http.Response, error) {
		return ctx.RoundTrip(req)
	}
	if cfResponse, passed, err := solveCloudFlare(resp, ctx.Req, caller); passed && err == nil {
		bodyBytes := ctx.UserData.([]byte)
		ctx.Req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		if cfResponse != nil {
			for _, cookie := range cfResponse.Cookies() {
				ctx.Req.AddCookie(cookie)
			}
		}

		if respRetry, err := ctx.RoundTrip(ctx.Req); err == nil && respRetry != nil {
			if set := cfResponse.Header.Get("Set-Cookie"); set != "" {
				respRetry.Header.Add("Set-Cookie", set)
			}

			return respRetry, nil
		}
	} else if err != nil {
		return nil, err
	}

	return nil, nil
}

func solveCloudFlare(resp *http.Response, originalReq *http.Request, caller callerFunc) (*http.Response, bool, error) {
	// Save current time for delay calculation
	now := time.Now()

	requestURL := originalReq.URL
	originalURL, _ := resp.Location()
	if originalURL == nil {
		originalURL = originalReq.URL
	}

	// Reading body and creating a new one to allow body read in other places
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("Body read error: %s", err)
	}
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	// If there is not <form> on the page - something is wrong
	if !reForm.Match(body) {
		dumpResponse(resp, originalReq, true, true)
		return nil, false, fmt.Errorf("Could not match Form regexp")
	}

	host := strings.Replace(requestURL.Host, ":443", "", -1)
	challengeForm := reForm.FindAllString(string(body), -1)[0]

	// Find <form method="">
	if !reFormMethod.MatchString(challengeForm) {
		return nil, false, fmt.Errorf("Could not match Form method regexp")
	}
	method := reFormMethod.FindAllStringSubmatch(challengeForm, -1)[0][1]

	// Find <form action="">
	if !reFormAction.MatchString(challengeForm) {
		return nil, false, fmt.Errorf("Could not match Form action regexp")
	}
	action := reFormAction.FindAllStringSubmatch(challengeForm, -1)[0][1]

	submitURL := fmt.Sprintf("%s://%s%s", requestURL.Scheme, host, strings.Split(action, "?")[0])
	if method == "POST" {
		submitURL = fmt.Sprintf("%s://%s%s", requestURL.Scheme, host, action)
	}

	formGet := url.Values{}
	formPost := url.Values{}

	// Split action's url query params. It will be needed if the form should be submitted with GET
	if len(strings.Split(action, "?")) > 1 {
		for _, param := range strings.Split(strings.Split(action, "?")[1], "&") {
			params := strings.Split(param, "=")
			formGet.Set(params[0], params[1])
		}
	}

	if !reFormInput.MatchString(challengeForm) {
		return nil, false, fmt.Errorf("Could not match Form Input regexp")
	}

	// Collect all the <input> from the challenge form for futher submition
	for _, input := range reFormInput.FindAllString(challengeForm, -1) {
		if !reFormInputName.MatchString(input) || !reFormInputValue.MatchString(input) {
			continue
		}

		if reFormInputName.FindStringSubmatch(input)[1] != "jschl_answer" {
			if method == "POST" {
				formPost.Set(reFormInputName.FindStringSubmatch(input)[1], reFormInputValue.FindStringSubmatch(input)[1])
			} else if method == "GET" {
				formGet.Set(reFormInputName.FindStringSubmatch(input)[1], reFormInputValue.FindStringSubmatch(input)[1])
			}
		}
	}

	// Check for mandatory parameters
	if method == "POST" {
		for _, k := range []string{"jschl_vc", "pass"} {
			if formPost.Get(k) == "" {
				return nil, false, fmt.Errorf("%s is missing from challenge form", k)
			}
		}
	} else if method == "GET" {
		for _, k := range []string{"jschl_vc", "pass"} {
			if formGet.Get(k) == "" {
				return nil, false, fmt.Errorf("%s is missing from challenge form", k)
			}
		}
	}

	// Do the actual answer calculation, also get desired delay.
	answer, delay, err := solveChallenge(body, host)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot solve the challenge: %s", err)
	}

	if method == "POST" {
		formPost.Set("jschl_answer", answer)
	} else if method == "GET" {
		formGet.Set("jschl_answer", answer)
	}

	// Sleep if needed, before sending answer to CloudFlare
	diff := time.Since(now).Milliseconds()
	sleepDuration := math.Max(delay-float64(diff), 0)
	if sleepDuration > 0 {
		if LogEnabled {
			log.Debugf("Sleeping for %v milliseconds before sending answer to Cloudflare", sleepDuration)
		}
		time.Sleep(time.Duration(sleepDuration) * time.Millisecond)
	}

	// Prepare the Request
	var req *http.Request

	if method == "POST" {
		if req, err = http.NewRequest("POST", submitURL, strings.NewReader(formPost.Encode())); err != nil {
			return nil, false, fmt.Errorf("Cannot create HTTP request: %s", err)
		}
	} else if method == "GET" {
		if req, err = http.NewRequest("GET", submitURL, strings.NewReader(formGet.Encode())); err != nil {
			return nil, false, fmt.Errorf("Cannot create HTTP request: %s", err)
		}
	}

	// Copy headers from old request to new request to make sure we use the same
	copyRequestHeaders(originalReq, req)

	// Copy cookies from Cloudflare response to new request
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}

	// Set Referer properly
	if originalURL != nil {
		req.Header.Del("Referer")
		req.Header.Add("Referer", strings.Replace(originalURL.String(), ":443", "", -1))
	}

	if method == "POST" {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	} else if method == "GET" {
		req.URL.RawQuery = formGet.Encode()
	}

	if LogEnabled {
		dumpRequest(req, true, LogBodyEnabled)
	} else {
		dumpRequest(req, false, false)
	}

	// Sending the answer
	redirect, err := caller(req)
	if LogEnabled {
		dumpResponse(redirect, req, true, LogBodyEnabled)
	} else {
		dumpResponse(redirect, req, false, false)
	}

	if err != nil {
		if LogEnabled {
			log.Debugf("Could not finish CloudFlare: %#v", err)
		}
	} else if redirect.StatusCode == 503 {
		return nil, false, fmt.Errorf("Response after CloudFlare answer is still blocked with 503")
	}

	// Everything is fine and we are finishing
	return redirect, true, nil
}

func solveChallenge(body []byte, host string) (answer string, delay float64, err error) {
	javascript := reJavaScript.FindStringSubmatch(string(body))[1]

	if !reChallenge.MatchString(javascript) {
		return answer, delay, fmt.Errorf("Cannot match challenge regexp")
	}

	challenges := reChallenge.FindStringSubmatch(javascript)
	challenge, ms := challenges[1], challenges[2]

	// This is a special case found sometimes, "italics" should be changed,
	//   to allow Otto to execute the JS
	challenge = reReplaceItalics.ReplaceAllString(challenge, `"<i></i>"`)

	innerHTML := ""
	for _, i := range strings.Split(javascript, ";") {
		tokens := strings.Split(strings.TrimSpace(i), "=")
		if strings.TrimSpace(tokens[0]) == "k" {
			k := strings.Trim(strings.TrimSpace(tokens[1]), " '")
			reInnerHTML := regexp.MustCompile(`(?s)\<div.*?id\=\"` + k + `\".*?\>(.*?)\<\/div\>`)
			if !reInnerHTML.Match(body) {
				continue
			}

			innerHTML = reInnerHTML.FindStringSubmatch(string(body))[1]
		}
	}

	// This is the actual js, that should be run
	challenge = fmt.Sprintf(`
		var document = {
			createElement: function () {
			  return { firstChild: { href: "http://%s/" } }
			},
			getElementById: function () {
			  return {"innerHTML": "%s"};
			}
		  };
		%s; return a.value
	`, host, innerHTML, challenge)

	// Check for Delay in the body
	if ms != "" {
		msi, _ := strconv.Atoi(ms)
		delay = float64(msi)
	} else {
		delay = 8000
	}

	// Run Javascript to get the answer
	jsEngine := otto.New()
	data, err := jsEngine.Eval("(function () {" + challenge + "})()")
	if err != nil {
		return answer, delay, fmt.Errorf("JS Execution error: %s", err)
	}

	answer, err = data.ToString()
	if err != nil {
		return answer, delay, fmt.Errorf("JS Result parse error: %s", err)
	}

	return
}

func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header)
	for k, s := range r.Header {
		r2.Header[k] = s
	}
	return r2
}

func copyRequestHeaders(old *http.Request, new *http.Request) {
	// new.Header = make(http.Header)
	for k, s := range old.Header {
		if new.Header.Get("k") == "" {
			new.Header[k] = s
		}
	}
}

func dumpRequest(req *http.Request, details bool, body bool) {
	log.Debugf("%s %s", req.Method, req.URL)

	if !details {
		return
	}

	if req == nil {
		log.Debugf("REQUEST: nil")
		return
	}

	dump, _ := httputil.DumpRequestOut(req, body)
	log.Debugf("REQUEST:\n%s", dump)
}

func dumpResponse(resp *http.Response, req *http.Request, details bool, body bool) {
	if resp != nil {
		log.Debugf("%d %s", resp.StatusCode, req.URL.String())
	} else {
		log.Debugf("ERR %s", req.URL.String())
		return
	}

	if !details {
		return
	}

	if resp == nil {
		log.Debugf("RESPONSE: nil")
		return
	}

	dump, _ := httputil.DumpResponse(resp, body)
	log.Debugf("RESPONSE:\n%s", dump)
}

// IsCloudFlared checks whether http.Response is blocked by CloudFlare
func IsCloudFlared(resp *http.Response) bool {
	return (resp.StatusCode == 503 || resp.StatusCode == 429) &&
		strings.HasPrefix(resp.Header.Get("Server"), "cloudflare")
}

// Max just a simple Max of int64
func Max(x, y int64) int64 {
	if x < y {
		return y
	}
	return x
}
