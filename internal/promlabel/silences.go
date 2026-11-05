package promlabel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const silencePathPrefix = "/api/v2/silence/"

var silenceIDPattern = regexp.MustCompile(`^[0-9a-fA-F-]{1,64}$`)

// matcher is a silence matcher. isEqual defaults to true when absent.
type matcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"isRegex"`
	IsEqual *bool  `json:"isEqual,omitempty"`
}

func (m matcher) equality() bool {
	return !m.IsRegex && (m.IsEqual == nil || *m.IsEqual)
}

// silence is the whole Alertmanager silence. Requests are rebuilt from it rather
// than edited as raw JSON: encoding/json matches keys case-insensitively, so a
// raw edit of "matchers" or "id" would leave an alias like "ID" for the backend
// to read unchecked.
type silence struct {
	ID        string          `json:"id,omitempty"`
	Matchers  []matcher       `json:"matchers"`
	StartsAt  json.RawMessage `json:"startsAt,omitempty"`
	EndsAt    json.RawMessage `json:"endsAt,omitempty"`
	CreatedBy json.RawMessage `json:"createdBy,omitempty"`
	Comment   json.RawMessage `json:"comment,omitempty"`
}

// owns reports whether a silence belongs to the caller: for every enforced
// label it has an equality matcher on a value the caller holds. A regex or
// negative matcher doesn't count, because either could span tenants.
func owns(ls []Label, ms []matcher) bool {
	for _, l := range ls {
		found := false
		for _, m := range ms {
			if m.Name == l.Name && m.equality() && l.allows(m.Value) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// filterSilences keeps the silences the caller owns.
func filterSilences(body []byte, ls []Label) ([]byte, error) {
	var all []json.RawMessage
	if err := json.Unmarshal(body, &all); err != nil {
		return nil, err
	}
	kept := []json.RawMessage{}
	for _, raw := range all {
		var s silence
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		if owns(ls, s.Matchers) {
			kept = append(kept, raw)
		}
	}
	return json.Marshal(kept)
}

var errForbidden = errors.New("forbidden")

// scopeMatchers applies the create rules: each enforced label ends up with one
// equality matcher on a value the caller holds, and at least one other matcher
// remains, so a silence can't cover everything a tenant has by accident.
func scopeMatchers(ls []Label, ms []matcher) ([]matcher, error) {
	enforced := make(map[string]bool, len(ls))
	for _, l := range ls {
		enforced[l.Name] = true
	}

	out := make([]matcher, 0, len(ms)+len(ls))
	for _, m := range ms {
		if !enforced[m.Name] {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("need at least one matcher besides the enforced labels")
	}

	for _, l := range ls {
		var named []matcher
		for _, m := range ms {
			if m.Name == l.Name {
				named = append(named, m)
			}
		}
		switch {
		case len(named) > 1:
			return nil, fmt.Errorf("more than one matcher on label %q", l.Name)
		case len(named) == 1:
			if !named[0].equality() || !l.allows(named[0].Value) {
				return nil, fmt.Errorf("%w: matcher on label %q", errForbidden, l.Name)
			}
			out = append(out, named[0])
		case len(l.Values) == 1:
			out = append(out, matcher{Name: l.Name, Value: l.Values[0]})
		default:
			return nil, fmt.Errorf("label %q has several allowed values, name one with an equality matcher", l.Name)
		}
	}
	return out, nil
}

// postSilence creates or updates a silence.
func (h *Handler) postSilence(w http.ResponseWriter, r *http.Request, scope Scope) {
	raw, err := readBody(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	var s silence
	if err := json.Unmarshal(raw, &s); err != nil {
		http.Error(w, "can't decode silence: "+err.Error(), http.StatusBadRequest)
		return
	}

	if s.ID != "" && !h.checkOwner(w, r, scope, s.ID) {
		return
	}

	scoped, err := scopeMatchers(scope.Labels, s.Matchers)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errForbidden) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.Matchers = scoped
	body, err := json.Marshal(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	r.URL.RawQuery = ""
	setBody(r, string(body), "application/json")
	h.next.ServeHTTP(w, r)
}

func (h *Handler) deleteSilence(w http.ResponseWriter, r *http.Request, scope Scope) {
	id := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, scope.Prefix), silencePathPrefix)
	if !h.checkOwner(w, r, scope, id) {
		return
	}
	r.URL.RawQuery = ""
	dropBody(r)
	h.next.ServeHTTP(w, r)
}

// checkOwner fetches a silence from the target and reports whether the caller
// owns it, writing the response itself when not. A silence that doesn't exist
// answers the same 403 as another tenant's, so IDs can't be probed.
func (h *Handler) checkOwner(w http.ResponseWriter, r *http.Request, scope Scope, id string) bool {
	if !silenceIDPattern.MatchString(id) {
		http.Error(w, "invalid silence id", http.StatusBadRequest)
		return false
	}

	target := h.source.Current().TargetURL().JoinPath(scope.Prefix, silencePathPrefix, id)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil) // #nosec G704 -- the configured target plus an ID checked against silenceIDPattern
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return false
	}
	// The same credentials and tenant headers the forwarded request will carry.
	req.Header = r.Header.Clone()
	for _, name := range []string{"Content-Length", "Content-Type", "Accept-Encoding"} {
		req.Header.Del(name)
	}

	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "prom_label_proxy: silence lookup failed", "err", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return false
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	default:
		h.logger.ErrorContext(r.Context(), "prom_label_proxy: silence lookup failed", "status", resp.StatusCode)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return false
	}

	body, err := readResponse(resp)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return false
	}
	var s silence
	if err := json.Unmarshal(body, &s); err != nil {
		h.logger.ErrorContext(r.Context(), "prom_label_proxy: silence lookup unreadable", "err", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return false
	}
	if !owns(scope.Labels, s.Matchers) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}
