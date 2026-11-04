package trustclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLegacyAndAccountRouteCompatibility(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		t.Run(map[bool]string{true: "legacy", false: "account"}[legacy], func(t *testing.T) {
			calls := []string{}
			prefix := "/rest/api/v1/"
			account := "acct/"
			if legacy {
				account = ""
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.URL.EscapedPath())
				if r.Header.Get("x-api-token") != "fixture-token" {
					t.Error("missing token")
				}
				if r.URL.Path == prefix+"token/"+account+"get/fixture-token" {
					_, _ = io.WriteString(w, `{"secret_id":"bound-secret"}`)
					return
				}
				if strings.Contains(r.URL.Path, "denied") {
					w.WriteHeader(403)
					return
				}
				_, _ = io.WriteString(w, `{"id":"fixture"}`)
			}))
			defer server.Close()
			builder := NewBuilder().URL(server.URL).APIToken("fixture-token").LegacyAPI(legacy)
			if !legacy {
				builder.AccountID("acct")
			}
			client, err := builder.Build(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx := context.Background()
			for _, call := range []func() (string, error){func() (string, error) { return client.GetSecret(ctx, "") }, func() (string, error) { return client.FetchSecret(ctx, "a/b") }, func() (string, error) { return client.GetCertificate(ctx, "") }, func() (string, error) { return client.FetchCertificateBundle(ctx, "cert-token") }} {
				if _, err := call(); err != nil {
					t.Fatal(err)
				}
			}
			want := []string{prefix + "token/" + account + "get/fixture-token", prefix + "secret/" + account + "get/bound-secret", prefix + "secret/" + account + "fetch/a%2Fb", prefix + "cert/" + account + "get/fixture-token", prefix + "cert/" + account + "fetch-bundle/cert-token"}
			if strings.Join(calls, "\n") != strings.Join(want, "\n") {
				t.Fatalf("paths %v", calls)
			}
			before := len(calls)
			if _, err := client.FetchSecret(ctx, "denied"); err == nil {
				t.Fatal("expected denial")
			}
			if len(calls) != before+1 {
				t.Fatal("denial caused a fallback")
			}
		})
	}
}
