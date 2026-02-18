package payloads

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestWebSocketGenerator_Type(t *testing.T) {
	g := NewWebSocketGenerator()
	if got := g.Type(); got != "websocket" {
		t.Errorf("Type() = %q, want %q", got, "websocket")
	}
}

func TestWebSocketGenerator_RelevantPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "/ws", path: "/ws"},
		{name: "/websocket", path: "/websocket"},
		{name: "/socket.io", path: "/socket.io"},
		{name: "/hub", path: "/api/hub"},
		{name: "/signalr", path: "/signalr/negotiate"},
		{name: "/stream", path: "/api/stream"},
		{name: "/events", path: "/events/live"},
	}

	g := NewWebSocketGenerator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := types.Endpoint{
				Method: "GET",
				Path:   tt.path,
				Parameters: []types.Parameter{
					{Name: "token", In: "query", Type: "string"},
				},
			}
			param := &endpoint.Parameters[0]

			payloads := g.Generate(endpoint, param)
			if len(payloads) == 0 {
				t.Errorf("expected payloads for WebSocket-relevant path %q, got 0", tt.path)
			}
			for i, p := range payloads {
				if p.Type != types.AttackWebSocket {
					t.Errorf("payload[%d].Type = %q, want %q", i, p.Type, types.AttackWebSocket)
				}
			}
		})
	}
}

func TestWebSocketGenerator_IrrelevantPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "/api/users", path: "/api/users"},
		{name: "/api/login", path: "/api/login"},
		{name: "/health", path: "/health"},
		{name: "/api/products", path: "/api/products"},
	}

	g := NewWebSocketGenerator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := types.Endpoint{
				Method: "GET",
				Path:   tt.path,
				Parameters: []types.Parameter{
					{Name: "id", In: "query", Type: "string"},
				},
			}
			param := &endpoint.Parameters[0]

			payloads := g.Generate(endpoint, param)
			if len(payloads) != 0 {
				t.Errorf("expected 0 payloads for non-WebSocket path %q, got %d", tt.path, len(payloads))
			}
		})
	}
}

func TestWebSocketGenerator_TransportMetadata(t *testing.T) {
	g := NewWebSocketGenerator()

	endpoint := types.Endpoint{
		Method: "GET",
		Path:   "/ws/chat",
		Parameters: []types.Parameter{
			{Name: "token", In: "query", Type: "string"},
		},
	}
	param := &endpoint.Parameters[0]

	payloads := g.Generate(endpoint, param)
	if len(payloads) == 0 {
		t.Fatal("expected payloads for WebSocket endpoint, got 0")
	}

	for i, p := range payloads {
		transport, ok := p.Metadata["transport"]
		if !ok {
			t.Errorf("payload[%d] missing metadata[\"transport\"]", i)
			continue
		}
		if transport != "websocket" {
			t.Errorf("payload[%d].Metadata[\"transport\"] = %q, want %q", i, transport, "websocket")
		}
	}
}
