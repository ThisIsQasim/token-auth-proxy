package authn

import (
	"encoding/base64"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// loginMethodCookie remembers which method the user picked, so a later
// credential-less navigation goes straight to it instead of back to the
// picker. It's a preference, not a credential, so it carries no
// signature. For Basic it is also what makes the flow work at all: the
// browser only sends cached Basic credentials after a 401 challenge, and
// the cookie is what turns the next credential-less request into one.
const loginMethodCookie = "tap_login_method"

// loginMethod is one way a browser with no credential can sign in.
type loginMethod struct {
	kind   string // "saml" | "basic" | "jwt"
	source string // JWT source name, for kind "jwt"
	label  string
}

func (m loginMethod) cookieValue() string {
	if m.kind == "jwt" {
		return "jwt:" + base64.RawURLEncoding.EncodeToString([]byte(m.source))
	}
	return m.kind
}

func (m loginMethod) href(returnTo string) string {
	q := url.Values{"return_to": {returnTo}}
	if m.kind == "jwt" {
		q.Set("source", m.source)
	}
	return config.LoginPathPrefix + "/" + m.kind + "?" + q.Encode()
}

// loginMethods lists the configured methods in a fixed order: JWT
// sources with login (config order), SAML, then Basic.
func loginMethods(auth config.InboundAuthConfig) []loginMethod {
	var out []loginMethod
	for _, j := range auth.LoginSources() {
		out = append(out, loginMethod{kind: "jwt", source: j.Name, label: "Sign in with " + loginLabel(j)})
	}
	if auth.SAMLEnabled() {
		out = append(out, loginMethod{kind: "saml", label: "Sign in with SAML"})
	}
	if auth.BasicEnabled() {
		out = append(out, loginMethod{kind: "basic", label: "Sign in with username and password"})
	}
	return out
}

// chosenMethod returns the method named by the preference cookie, if it
// is still configured.
func chosenMethod(r *http.Request, methods []loginMethod) (loginMethod, bool) {
	c, err := r.Cookie(loginMethodCookie)
	if err != nil {
		return loginMethod{}, false
	}
	for _, m := range methods {
		if m.cookieValue() == c.Value {
			return m, true
		}
	}
	return loginMethod{}, false
}

// browserNav reports whether r looks like a browser navigation, the only
// kind of request worth redirecting to a login page.
func browserNav(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

func setMethodCookie(w http.ResponseWriter, r *http.Request, m loginMethod) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the request scheme; this is a UI preference, not a credential
		Name:     loginMethodCookie,
		Value:    m.cookieValue(),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
	})
}

var pickerTmpl = template.Must(template.New("picker").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
:root { color-scheme: light dark; --bg: #f6f7f9; --fg: #1a1c20; --card: #fff; --line: #d5d9e0; --accent: #2b5fd9; --accent-fg: #fff; }
@media (prefers-color-scheme: dark) { :root { --bg: #14161a; --fg: #e8eaee; --card: #1d2026; --line: #343942; --accent: #6b93f2; --accent-fg: #101319; } }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px; background: var(--bg); color: var(--fg); font: 16px/1.4 system-ui, sans-serif; }
main { width: 100%; max-width: 380px; padding: 28px 24px; background: var(--card); border: 1px solid var(--line); border-radius: 10px; }
h1 { margin: 0 0 20px; font-size: 20px; }
a { display: block; margin-top: 10px; padding: 11px 14px; border-radius: 6px; background: var(--accent); color: var(--accent-fg); text-align: center; text-decoration: none; font-weight: 600; overflow-wrap: anywhere; }
a:focus-visible { outline: 3px solid var(--fg); outline-offset: 2px; }
</style>
{{if .CSS}}<style>{{.CSS}}</style>
{{end}}</head>
<body>
<main class="tap-login">
<h1 class="tap-login-title">Sign in</h1>
{{range .Items}}<a class="tap-login-method" href="{{.Href}}">{{.Label}}</a>
{{end}}</main>
</body>
</html>
`))

type pickerItem struct {
	Href  template.URL
	Label string
}

func servePicker(w http.ResponseWriter, methods []loginMethod, returnTo, css string) {
	items := make([]pickerItem, len(methods))
	for i, m := range methods {
		items[i] = pickerItem{Href: template.URL(m.href(returnTo)), Label: m.label} // #nosec G203 -- built from a fixed path and url.Values.Encode
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = pickerTmpl.Execute(w, struct {
		Items []pickerItem
		CSS   template.CSS
	}{items, template.CSS(css)}) // #nosec G203 -- operator config, checked for </style by config validation
}

// redirectToPicker sends a credential-less browser to the picker,
// remembering where it was headed.
func redirectToPicker(w http.ResponseWriter, r *http.Request) {
	q := url.Values{"return_to": {r.URL.RequestURI()}}
	http.Redirect(w, r, config.LoginPathPrefix+"?"+q.Encode(), http.StatusFound)
}

// isLoginRoute reports whether path is the picker or one of its
// per-method entry points.
func isLoginRoute(path string) bool {
	return path == config.LoginPathPrefix || strings.HasPrefix(path, config.LoginPathPrefix+"/")
}

// serveLoginRoute handles the picker page and /_tap/login/{saml,basic,jwt}.
// A method's route records the choice and then starts that method; for
// Basic it answers with the challenge, or redirects back if the request
// already carries valid credentials.
func serveLoginRoute(w http.ResponseWriter, r *http.Request, cfg *config.Config, d loginDeps, logger *slog.Logger) {
	auth := cfg.Inbound.Auth
	methods := loginMethods(auth)
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var m loginMethod
	switch r.URL.Path {
	case config.LoginPathPrefix, config.LoginPathPrefix + "/":
		servePicker(w, methods, returnTo, loginPageCSS(auth))
		return
	case config.LoginPathPrefix + "/saml":
		m = loginMethod{kind: "saml"}
	case config.LoginPathPrefix + "/basic":
		m = loginMethod{kind: "basic"}
	case config.LoginPathPrefix + "/jwt":
		m = loginMethod{kind: "jwt", source: r.URL.Query().Get("source")}
	default:
		http.NotFound(w, r)
		return
	}
	found := false
	for _, c := range methods {
		if c.kind == m.kind && c.source == m.source {
			found = true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}

	switch m.kind {
	case "basic":
		outcome, _ := enforceBasic(w, r, *auth.Basic, d.basic, logger)
		switch outcome {
		case basicAllowed:
			setMethodCookie(w, r, m)
			http.Redirect(w, r, returnTo, http.StatusFound) //nolint:gosec // returnTo went through sanitizeReturnTo, so it is a same-origin path
		case basicNoCredential:
			rejectChallenges(w, logger, r, reasonNoCredential, []string{basicChallenge(auth.Basic.Realm)})
		}
	case "saml":
		setMethodCookie(w, r, m)
		runSAMLLogin(w, r, cfg, d, returnTo, logger)
	case "jwt":
		setMethodCookie(w, r, m)
		src := jwtLoginSource(auth, m.source)
		d.login.Start(w, r, src, returnTo)
	}
}

// runSAMLLogin starts the SAML flow as if the browser had asked for
// returnTo directly: samlsp remembers the request URL and sends the
// browser back to it after the ACS.
func runSAMLLogin(w http.ResponseWriter, r *http.Request, cfg *config.Config, d loginDeps, returnTo string, logger *slog.Logger) {
	mw, err := d.saml.Provider(*cfg.Inbound.Auth.SAML)
	if err != nil {
		rejectUnavailable(w, logger, r, reasonSAMLMetadataUnavailable, err, d.saml.retry)
		return
	}
	target, err := url.ParseRequestURI(returnTo)
	if err != nil {
		target = &url.URL{Path: "/"}
	}
	r2 := r.Clone(r.Context())
	r2.URL = target
	r2.RequestURI = returnTo
	enforceSAML(mw, http.RedirectHandler(returnTo, http.StatusFound)).ServeHTTP(w, r2)
}

func jwtLoginSource(auth config.InboundAuthConfig, name string) config.JWTSource {
	for _, j := range auth.LoginSources() {
		if j.Name == name {
			return j
		}
	}
	return config.JWTSource{}
}

// loginDeps bundles the registries the login routes need.
type loginDeps struct {
	saml  *SAMLRegistry
	basic *BasicRegistry
	login *LoginRegistry
}

func loginLabel(j config.JWTSource) string {
	if j.Login.Label != "" {
		return j.Login.Label
	}
	return j.Name
}

func loginPageCSS(auth config.InboundAuthConfig) string {
	if auth.LoginPage == nil {
		return ""
	}
	return auth.LoginPage.CSS
}
