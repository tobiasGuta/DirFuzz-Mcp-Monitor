package httpclient

import "testing"

func TestHasCompleteChunkedBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "complete chunked without trailers",
			body: "4\r\nWiki\r\n0\r\n\r\n",
			want: true,
		},
		{
			name: "complete chunked with trailers",
			body: "4\r\nWiki\r\n0\r\nExpires: now\r\n\r\n",
			want: true,
		},
		{
			name: "incomplete zero chunk",
			body: "4\r\nWiki\r\n0\r\n",
			want: false,
		},
		{
			name: "lf only complete",
			body: "4\nWiki\n0\n\n",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasCompleteChunkedBody([]byte(tt.body))
			if got != tt.want {
				t.Fatalf("hasCompleteChunkedBody() = %v, want %v", got, tt.want)
			}
		})
	}
}
