package admin

import (
	"github.com/google/uuid"
	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/httpx"
	"net/http"
)

// This bounded delegated decision cannot choose a permission or impersonate a
// user on another operation. Ingress retains the service surface's router mTLS.
func (h *Handler) handleBuyersDispatchAuthority(w http.ResponseWriter, r *http.Request) {
	actor, e := extractServiceSubject(r)
	if e != nil {
		writeError(w, e)
		return
	}
	if actor != "svc:aurumskynet-buyers" {
		apierror.New("forbidden", 403, "buyers service required").Write(w)
		return
	}
	var in struct {
		Seller string `json:"seller"`
		Actor  string `json:"actor"`
	}
	if httpx.ReadJSON(r, &in) != nil || !buyersUUID(in.Seller) || !buyersUUID(in.Actor) {
		apierror.New("bad_request", 400, "canonical seller and actor UUID required").Write(w)
		return
	}
	result, err := h.engine.CheckAccess(r.Context(), in.Actor, "tenant", "wildberries:"+in.Seller, "campaign_module", "buyers.write")
	if err != nil {
		apierror.New("unavailable", 503, "authorization unavailable").Write(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, struct {
		Allowed bool `json:"allowed"`
	}{result.Allowed})
}
func buyersUUID(s string) bool {
	v, e := uuid.Parse(s)
	return e == nil && v != uuid.Nil && v.String() == s
}
