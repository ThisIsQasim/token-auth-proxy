package promlabel

// The response filters and silence handling in this package are adapted from
// prometheus-community/prom-label-proxy (injectproxy/rules.go, silences.go),
// Copyright The Prometheus Authors, licensed under the Apache License 2.0.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// maxResponseBytes bounds a response held in memory for filtering.
const maxResponseBytes = 64 << 20

// bodyFilter rewrites a successful response body for the caller's labels.
type bodyFilter func(body []byte, ls []Label) ([]byte, error)

// dataFilter rewrites the data field of a Prometheus API response.
type dataFilter func(data json.RawMessage, ls []Label) (any, error)

type filterKey struct{}

type responseFilter struct {
	filter bodyFilter
	labels []Label
}

// filtered forwards r with its Prometheus API response filtered.
func (h *Handler) filtered(w http.ResponseWriter, r *http.Request, scope Scope, f dataFilter) {
	h.filteredRaw(w, r, scope, apiFilter(f))
}

// partialResponseHeaders ask for something other than the full, plain body a
// filter has to read.
var partialResponseHeaders = []string{"Accept-Encoding", "Range", "If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"}

// filteredRaw forwards r with the response body passed through f.
func (h *Handler) filteredRaw(w http.ResponseWriter, r *http.Request, scope Scope, f bodyFilter) {
	dropBody(r)
	for _, name := range partialResponseHeaders {
		r.Header.Del(name)
	}
	ctx := context.WithValue(r.Context(), filterKey{}, responseFilter{filter: f, labels: scope.Labels})
	h.next.ServeHTTP(w, r.WithContext(ctx))
}

// ModifyResponse is the reverse proxy hook applying a request's response
// filter. Returning an error makes the proxy answer 502, so a body that can't
// be filtered never reaches the caller as it came. Only error statuses pass
// unread: they carry no rules, alerts or silences, where a 206 or 203 might.
func ModifyResponse(resp *http.Response) error {
	f, ok := resp.Request.Context().Value(filterKey{}).(responseFilter)
	if !ok || resp.StatusCode >= http.StatusBadRequest {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("prom_label_proxy: unexpected status %d", resp.StatusCode)
	}

	body, err := readResponse(resp)
	if err != nil {
		return fmt.Errorf("prom_label_proxy: read response: %w", err)
	}
	filtered, err := f.filter(body, f.labels)
	if err != nil {
		return fmt.Errorf("prom_label_proxy: filter response: %w", err)
	}

	resp.Body = io.NopCloser(bytes.NewReader(filtered))
	resp.ContentLength = int64(len(filtered))
	resp.Header.Set("Content-Length", strconv.Itoa(len(filtered)))
	return nil
}

// readResponse returns the decoded body. A backend may compress regardless of
// the request, so gzip is handled and any other encoding refused.
func readResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	var reader io.Reader = resp.Body
	switch enc := resp.Header.Get("Content-Encoding"); enc {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer func() { _ = gz.Close() }()
		reader = gz
		resp.Header.Del("Content-Encoding")
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", enc)
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("response over %d bytes", maxResponseBytes)
	}
	return body, nil
}

// apiFilter applies f to the data of a successful Prometheus API response,
// leaving the rest of the envelope alone.
func apiFilter(f dataFilter) bodyFilter {
	return func(body []byte, ls []Label) ([]byte, error) {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, err
		}
		var status string
		if err := json.Unmarshal(envelope["status"], &status); err != nil || status != "success" {
			return nil, errors.New("not a successful API response")
		}
		filtered, err := f(envelope["data"], ls)
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(filtered)
		if err != nil {
			return nil, err
		}
		envelope["data"] = data
		return json.Marshal(envelope)
	}
}

// visible reports whether an entry with these labels carries every enforced
// label with a value the caller holds.
func visible(entry map[string]string, ls []Label) bool {
	for _, l := range ls {
		if !l.allows(entry[l.Name]) {
			return false
		}
	}
	return true
}

// labeled is the one field the filters look at. Entries are otherwise kept as
// raw JSON, so fields a backend adds to the standard shape survive.
type labeled struct {
	Labels map[string]string `json:"labels"`
}

func keepLabelled(entries []json.RawMessage, ls []Label) ([]json.RawMessage, error) {
	kept := []json.RawMessage{}
	for _, raw := range entries {
		var e labeled
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		if visible(e.Labels, ls) {
			kept = append(kept, raw)
		}
	}
	return kept, nil
}

// filterRules keeps the rules carrying the enforced labels, dropping groups
// left empty.
func filterRules(data json.RawMessage, ls []Label) (any, error) {
	var d map[string]json.RawMessage
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	var groups []map[string]json.RawMessage
	if err := json.Unmarshal(d["groups"], &groups); err != nil {
		return nil, err
	}

	kept := []map[string]json.RawMessage{}
	for _, g := range groups {
		var rules []json.RawMessage
		if err := json.Unmarshal(g["rules"], &rules); err != nil {
			return nil, err
		}
		visibleRules, err := keepLabelled(rules, ls)
		if err != nil {
			return nil, err
		}
		if len(visibleRules) == 0 {
			continue
		}
		if g["rules"], err = json.Marshal(visibleRules); err != nil {
			return nil, err
		}
		kept = append(kept, g)
	}

	var err error
	if d["groups"], err = json.Marshal(kept); err != nil {
		return nil, err
	}
	return d, nil
}

// filterAlerts keeps the alerts carrying the enforced labels.
func filterAlerts(data json.RawMessage, ls []Label) (any, error) {
	var d map[string]json.RawMessage
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	var alerts []json.RawMessage
	if err := json.Unmarshal(d["alerts"], &alerts); err != nil {
		return nil, err
	}
	kept, err := keepLabelled(alerts, ls)
	if err != nil {
		return nil, err
	}
	if d["alerts"], err = json.Marshal(kept); err != nil {
		return nil, err
	}
	return d, nil
}
