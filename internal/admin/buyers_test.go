package admin

import (
	"bytes"
	"context"
	"github.com/ledatu/csar-authz/internal/engine"
	"github.com/ledatu/csar-authz/internal/store"
	"github.com/ledatu/csar-authz/internal/store/memory"
	"github.com/ledatu/csar-core/authzconfig"
	"github.com/ledatu/csar-core/gatewayctx"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuyersDelegatedAuthority(t *testing.T) {
	const actor = "00000000-0000-4000-8000-000000000001"
	const seller = "00000000-0000-4000-8000-000000000002"
	ctx := context.Background()
	s := memory.New()
	eng := engine.New(s)
	must(t, s.CreateRole(ctx, &store.Role{Name: "buyer_writer"}))
	must(t, s.AddPermission(ctx, &store.Permission{Role: "buyer_writer", Resource: "campaign_module", Action: "buyers.write"}))
	must(t, eng.AssignRole(ctx, actor, "buyer_writer", "tenant", "wildberries:"+seller))
	h := New(eng, nil, nil, slog.Default(), &authzconfig.AdminConfig{})
	mux := http.NewServeMux()
	h.RegisterServiceRoutes(mux)
	call := func(subject, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/svc/buyers/dispatch-authority", bytes.NewBufferString(body))
		r = r.WithContext(gatewayctx.NewContext(r.Context(), &gatewayctx.Identity{Subject: subject}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	body := `{"seller":"` + seller + `","actor":"` + actor + `"}`
	for _, subject := range []string{actor, "svc:aurumskynet-campaigns", ""} {
		w := call(subject, body)
		if w.Code == 200 {
			t.Fatalf("unexpected subject accepted %q", subject)
		}
	}
	w := call("svc:aurumskynet-buyers", body)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"allowed":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	other := strings.Replace(body, seller, "00000000-0000-4000-8000-000000000003", 1)
	w = call("svc:aurumskynet-buyers", other)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"allowed":false`) {
		t.Fatal("cross seller allowed")
	}
	must(t, eng.RevokeRole(ctx, actor, "buyer_writer", "tenant", "wildberries:"+seller))
	w = call("svc:aurumskynet-buyers", body)
	if !strings.Contains(w.Body.String(), `"allowed":false`) {
		t.Fatal("revocation cached")
	}
	for _, bad := range []string{`{}`, `{"seller":"bad","actor":"` + actor + `"}`, `{"seller":"` + seller + `","actor":"svc:buyers"}`} {
		if w = call("svc:aurumskynet-buyers", bad); w.Code != http.StatusBadRequest {
			t.Fatal(w.Code)
		}
	}
}
