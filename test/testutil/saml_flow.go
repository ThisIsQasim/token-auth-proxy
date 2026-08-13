package testutil

import (
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// StartProxySAML starts the real proxy binary with a SAML source
// pointed at idp, resolving the circular dependency between "the
// config needs the proxy's own externally-reachable sp_base_url" and
// "the proxy's address isn't known until it's listening": it first
// starts with a syntactically-valid but never-dialed placeholder
// sp_base_url (buildConfig("http://127.0.0.1:0")), discovers the real
// bound address the same way StartProxy does, then hot-reloads
// buildConfig again with the real sp_base_url in place and registers
// that same address as idp's recognized SP — exercising the real
// reload path, rather than racily pre-grabbing a free port before the
// server itself binds one.
//
// buildConfig must return the full config YAML for a given sp_base_url
// (including the matching value inside inbound.auth.saml.sp_base_url),
// and — by convention, fixed here rather than threaded through as a
// parameter — must set sp_entity_id to spBaseURL+"/saml/metadata".
// acsPath must match whatever buildConfig puts in
// inbound.auth.saml.acs_path — passed separately because this package
// doesn't parse the YAML it's handed, only idp.RegisterSP needs it as a
// literal string. env carries any extra environment variables the
// process needs (e.g. "NAME=value" for session_signing_key_env); nil
// for none.
func StartProxySAML(tb testing.TB, cfgPath string, idp *TestSAMLIDP, acsPath string, buildConfig func(spBaseURL string) string, env []string) *Process {
	tb.Helper()

	WriteAtomic(tb, cfgPath, buildConfig("http://127.0.0.1:0"))
	proc := StartProxyWith(tb, env, "--config", cfgPath)

	realBase := "http://" + proc.Addr
	idp.RegisterSP(realBase+"/saml/metadata", realBase+acsPath)
	WriteAtomic(tb, cfgPath, buildConfig(realBase))

	// The watcher's reload is async; give it a moment to actually swap
	// in the real sp_base_url before the caller starts driving a login
	// against it. A fixed sleep (not a poll) is good enough here: every
	// caller immediately follows up with its own request/assertion that
	// would itself fail loudly if the reload were somehow still pending.
	time.Sleep(200 * time.Millisecond)

	return proc
}

// NewCookieClient returns an *http.Client with a real cookie jar and
// redirect-following disabled (CheckRedirect returns
// http.ErrUseLastResponse), so a SAML login flow's individual
// redirects and Set-Cookie headers can each be inspected by the caller
// rather than being silently followed and discarded.
func NewCookieClient(tb testing.TB) *http.Client {
	tb.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		tb.Fatalf("new cookie jar: %v", err)
	}
	return &http.Client{
		Jar:     jar,
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var (
	formActionRe   = regexp.MustCompile(`<form method="post" action="([^"]+)"`)
	samlResponseRe = regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`)
	relayStateRe   = regexp.MustCompile(`name="RelayState" value="([^"]*)"`)
)

// CompleteSAMLLogin drives one full SP-initiated login round trip
// starting at startURL using client (its cookie jar carries the
// tracker cookie exactly like a real browser would): follows the SP's
// redirect to the IdP, extracts the auto-submitted
// SAMLResponse/RelayState/ACS URL from the IdP's response HTML (the
// ACS URL comes from the form's own action attribute — samlsp puts the
// SP's registered AssertionConsumerServiceURL there, so this never
// needs to be told the acs_path separately), and POSTs it back. Returns
// the ACS response itself — normally a redirect back to startURL's
// original path with the session cookie set — the caller's Body to
// close and status/headers to assert on; a follow-up request is still
// needed to confirm the session actually authenticates, since this
// only proves the login mechanics work.
func CompleteSAMLLogin(tb testing.TB, client *http.Client, startURL string) *http.Response {
	tb.Helper()

	startResp, err := client.Get(startURL) //nolint:noctx // test-only, startURL is the proxy under test's own address
	if err != nil {
		tb.Fatalf("start login: %v", err)
	}
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusFound {
		tb.Fatalf("expected a redirect to the idp starting login, got %d", startResp.StatusCode)
	}
	idpURL := startResp.Header.Get("Location")

	ssoResp, err := client.Get(idpURL) //nolint:noctx // test-only, idpURL is the fixture's own local server
	if err != nil {
		tb.Fatalf("fetch idp sso page: %v", err)
	}
	defer func() { _ = ssoResp.Body.Close() }()
	body, err := io.ReadAll(ssoResp.Body)
	if err != nil {
		tb.Fatalf("read idp sso body: %v", err)
	}
	if ssoResp.StatusCode != http.StatusOK {
		tb.Fatalf("expected the idp sso page to render 200, got %d:\n%s", ssoResp.StatusCode, body)
	}

	action := mustSubmatch(tb, formActionRe, string(body), "form action")
	// html.UnescapeString undoes html/template's attribute escaping
	// (e.g. "+" -> "&#43;") — a real browser does this automatically
	// via the DOM .value property before auto-submitting the form.
	samlResponse := html.UnescapeString(mustSubmatch(tb, samlResponseRe, string(body), "SAMLResponse"))
	relayState := html.UnescapeString(mustSubmatch(tb, relayStateRe, string(body), "RelayState"))

	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	acsResp, err := client.Post(action, "application/x-www-form-urlencoded", strings.NewReader(form.Encode())) //nolint:noctx // test-only
	if err != nil {
		tb.Fatalf("post to acs: %v", err)
	}
	return acsResp
}

func mustSubmatch(tb testing.TB, re *regexp.Regexp, body, what string) string {
	tb.Helper()
	m := re.FindStringSubmatch(body)
	if len(m) != 2 {
		tb.Fatalf("expected to find %s in idp response:\n%s", what, body)
	}
	return m[1]
}
