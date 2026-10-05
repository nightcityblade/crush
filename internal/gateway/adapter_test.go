package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/stretchr/testify/require"
)

// seenRequest is what a stub gateway received.
type seenRequest struct {
	req  *http.Request
	body []byte
}

// echoServer answers with body and reports the request over a channel, so the
// test observes it without racing the server goroutine.
func echoServer(t *testing.T, body string, contentType string) (*httptest.Server, <-chan seenRequest) {
	t.Helper()
	requests := make(chan seenRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		select {
		case requests <- seenRequest{req: r.Clone(r.Context()), body: raw}:
		default:
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		io.WriteString(w, body) //nolint:errcheck // test stub
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func TestRequestRewrite(t *testing.T) {
	t.Parallel()

	server, requests := echoServer(t, `{"ok":true}`, "application/json")

	adapter, err := New(&oauth.GatewaySpec{
		Request: `
			{
				url: "` + server.URL + `/gateway:generate?alt=sse",
				headers: {Authorization: ("Bearer " + .token), "X-Added": "yes"},
				drop_headers: ["x-goog-api-key"],
				body: {model: .body.model, request: .body, id: .request_id}
			}`,
		Response: `.body`,
	}, "at-123", nil)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://sdk.example.com/v1beta/models/m:generateContent",
		strings.NewReader(`{"model":"m","contents":[]}`))
	require.NoError(t, err)
	req.Header.Set("x-goog-api-key", "at-123")
	req.Header.Set("X-Original", "kept")

	client := &http.Client{Transport: adapter}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	seen := <-requests
	raw := seen.body
	require.Equal(t, "/gateway:generate", seen.req.URL.Path)
	require.Equal(t, "alt=sse", seen.req.URL.RawQuery)
	require.Equal(t, "Bearer at-123", seen.req.Header.Get("Authorization"))
	require.Equal(t, "yes", seen.req.Header.Get("X-Added"))
	require.Empty(t, seen.req.Header.Get("x-goog-api-key"), "a dropped header must not reach the gateway")
	require.Equal(t, "kept", seen.req.Header.Get("X-Original"))
	// The rewritten URL is addressed to its own host, not the SDK's.
	require.Equal(t, seen.req.Host, strings.TrimPrefix(server.URL, "http://"))

	var sent map[string]any
	require.NoError(t, json.Unmarshal(raw, &sent))
	require.Equal(t, "m", sent["model"])
	require.NotEmpty(t, sent["id"], "the program can label a request with the id it was given")
	require.NotNil(t, sent["request"])
}

func TestResponseRewriteUnary(t *testing.T) {
	t.Parallel()

	server, _ := echoServer(t, `{"response":{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}}`, "application/json")

	adapter, err := New(&oauth.GatewaySpec{
		Request:  `{}`,
		Response: `(.body.response // .body) | .usageMetadata //= {}`,
	}, "", nil)
	require.NoError(t, err)

	resp, err := (&http.Client{Transport: adapter}).Post(server.URL, "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// The envelope is gone and the field a mapper would dereference exists.
	require.JSONEq(t, `{"candidates":[{"content":{"parts":[{"text":"hi"}]}}],"usageMetadata":{}}`, string(body))
}

func TestStreamRewrite(t *testing.T) {
	t.Parallel()

	upstream := `data: {"response":{"candidates":[{"content":{"parts":[{"text":"a"}]}}],"usageMetadata":{"totalTokenCount":5}}}

data: {"response":{"candidates":[{"content":{"parts":[{"text":"b"}]},"finishReason":"STOP"}],"usageMetadata":{"totalTokenCount":9}}}

`
	server, _ := echoServer(t, upstream, "text/event-stream")

	// The program unwraps, keeps usage only where the turn ends, and appends
	// a closing event when the backend omitted one.
	adapter, err := New(&oauth.GatewaySpec{
		Request: `{}`,
		Response: `
			if .event then
				(.data.response // .data) as $r
				| (if ($r.candidates[0].finishReason != null) or .final
					then $r else ($r | del(.usageMetadata)) end) as $r2
				| if .final and ($r2.candidates[0].finishReason == null)
					then [$r2, {candidates:[{finishReason:"STOP"}]}]
					else [$r2] end
			else .body end`,
	}, "", nil)
	require.NoError(t, err)

	resp, err := (&http.Client{Transport: adapter}).Post(server.URL, "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	events := parseEvents(t, string(body))
	require.Len(t, events, 2, "each upstream event yields one rewritten event")

	// The first chunk is not the end of the turn, so its cumulative usage is
	// withheld: crush sums token counts across chunks.
	require.Nil(t, events[0]["usageMetadata"])
	require.Equal(t, "a", firstText(t, events[0]))

	// The final chunk keeps its usage and the turn's finish.
	require.NotNil(t, events[1]["usageMetadata"])
	require.Equal(t, "STOP", events[1]["candidates"].([]any)[0].(map[string]any)["finishReason"])
}

func TestStreamSynthesizesMissingFinish(t *testing.T) {
	t.Parallel()

	server, _ := echoServer(t, `data: {"response":{"candidates":[{"content":{"parts":[{"text":"hi"}]}}],"usageMetadata":{"totalTokenCount":7}}}`+"\n\n", "text/event-stream")

	adapter, err := New(&oauth.GatewaySpec{
		Request: `{}`,
		Response: `
			if .event then
				(.data.response // .data) as $r
				| (if ($r.candidates[0].finishReason != null) or .final
					then $r else ($r | del(.usageMetadata)) end) as $r2
				| if .final and ($r2.candidates[0].finishReason == null)
					then [$r2, {candidates:[{finishReason:"STOP"}]}]
					else [$r2] end
			else .body end`,
	}, "", nil)
	require.NoError(t, err)

	resp, err := (&http.Client{Transport: adapter}).Post(server.URL, "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	events := parseEvents(t, string(body))
	require.Len(t, events, 2, "a stream that ends without a finish reason gets one appended")
	require.NotNil(t, events[0]["usageMetadata"], "the last real chunk keeps the usage")
	require.Equal(t, "STOP", events[1]["candidates"].([]any)[0].(map[string]any)["finishReason"])
}

func TestStreamPassesNonJSONThrough(t *testing.T) {
	t.Parallel()

	server, _ := echoServer(t, ": keepalive\n\ndata: not json\n\ndata: {\"ok\":true}\n\n", "text/event-stream")

	adapter, err := New(&oauth.GatewaySpec{
		Request:  `{}`,
		Response: `if .event then [.data] else .body end`,
	}, "", nil)
	require.NoError(t, err)

	resp, err := (&http.Client{Transport: adapter}).Post(server.URL, "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// The unparsable event survives verbatim rather than being dropped or
	// failing the stream.
	require.Contains(t, string(body), "data: not json")
	require.Contains(t, string(body), `{"ok":true}`)
}

func TestAdapterRejectsBadPrograms(t *testing.T) {
	t.Parallel()

	_, err := New(&oauth.GatewaySpec{Request: `{`, Response: `.`}, "", nil)
	require.ErrorContains(t, err, "gateway request program")

	_, err = New(&oauth.GatewaySpec{Request: `.`, Response: `if`}, "", nil)
	require.ErrorContains(t, err, "gateway response program")

	_, err = New(&oauth.GatewaySpec{Request: `.`}, "", nil)
	require.ErrorContains(t, err, "needs both")
}

func parseEvents(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, block := range strings.Split(stream, "\n\n") {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		require.True(t, strings.HasPrefix(block, "data:"), "every event is a data line: %q", block)
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(block, "data:"))), &event))
		events = append(events, event)
	}
	return events
}

func firstText(t *testing.T, event map[string]any) string {
	t.Helper()
	candidates := event["candidates"].([]any)
	content := candidates[0].(map[string]any)["content"].(map[string]any)
	parts := content["parts"].([]any)
	return parts[0].(map[string]any)["text"].(string)
}
