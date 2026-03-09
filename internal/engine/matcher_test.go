package engine

import "testing"

func TestMatchResource(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Exact matches
		{"/api/v1/users", "/api/v1/users", true},
		{"/api/v1/users", "/api/v1/posts", false},
		{"/api/v1/users", "/api/v1/users/123", false},
		{"/", "/", true},

		// Single wildcard
		{"/api/v1/users/*", "/api/v1/users/123", true},
		{"/api/v1/users/*", "/api/v1/users/abc", true},
		{"/api/v1/users/*", "/api/v1/users", false},
		{"/api/v1/users/*", "/api/v1/users/123/posts", false},
		{"/api/*/users", "/api/v1/users", true},
		{"/api/*/users", "/api/v2/users", true},
		{"/*", "/anything", true},
		{"/*", "/", false},

		// Double wildcard
		{"/api/**", "/api", true},
		{"/api/**", "/api/v1", true},
		{"/api/**", "/api/v1/users", true},
		{"/api/**", "/api/v1/users/123/posts", true},
		{"/**", "/", true},
		{"/**", "/anything", true},
		{"/**", "/a/b/c/d", true},
		{"/api/**/posts", "/api/posts", true},
		{"/api/**/posts", "/api/v1/posts", true},
		{"/api/**/posts", "/api/v1/users/posts", true},
		{"/api/**/posts", "/api/v1/users/comments", false},

		// Mixed wildcards
		{"/api/*/users/**", "/api/v1/users", true},
		{"/api/*/users/**", "/api/v1/users/123", true},
		{"/api/*/users/**", "/api/v1/users/123/posts", true},
		{"/api/*/users/**", "/api/v1/posts", false},

		// Edge cases
		{"", "", true},
		{"/api", "/api/", true}, // trailing slash normalization via split
		{"/api/", "/api", true},
	}

	for _, tt := range tests {
		got := MatchResource(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("MatchResource(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestMatchAction(t *testing.T) {
	tests := []struct {
		permAction string
		reqAction  string
		want       bool
	}{
		{"*", "GET", true},
		{"*", "POST", true},
		{"*", "DELETE", true},
		{"GET", "GET", true},
		{"GET", "get", true},
		{"get", "GET", true},
		{"GET", "POST", false},
		{"POST", "GET", false},
	}

	for _, tt := range tests {
		got := MatchAction(tt.permAction, tt.reqAction)
		if got != tt.want {
			t.Errorf("MatchAction(%q, %q) = %v, want %v", tt.permAction, tt.reqAction, got, tt.want)
		}
	}
}

func BenchmarkMatchResourceExact(b *testing.B) {
	for b.Loop() {
		MatchResource("/api/v1/users", "/api/v1/users")
	}
}

func BenchmarkMatchResourceWildcard(b *testing.B) {
	for b.Loop() {
		MatchResource("/api/v1/users/*", "/api/v1/users/123")
	}
}

func BenchmarkMatchResourceDoubleWildcard(b *testing.B) {
	for b.Loop() {
		MatchResource("/api/**", "/api/v1/users/123/posts/456")
	}
}
