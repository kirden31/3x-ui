package sub

import (
	"encoding/json"
	"strings"

	"github.com/kirden31/3x-ui/v2/database/model"
)

// applyCustomPortRules mutates inbound in-place when inbound.Port in the target range.
// Changes:
//  - inbound.Port -> 443
//  - ensure stream.security == "tls" (we set it here to be explicit)
//  - tlsSettings.alpn = ["h3","h2"]
//  - tlsSettings.fingerprint = "random"
func applyCustomPortRules(inbound *model.Inbound) {
	if inbound == nil {
		return
	}

	if inbound.Port >= 10000 && inbound.Port <= 11000 {
		// set the port in the generated subscription context
		inbound.Port = 443

        // if listen is empty or loopback, use 0.0.0.0
		l := strings.TrimSpace(inbound.Listen)
		if l == "" || l == "127.0.0.1" || l == "localhost" || strings.HasPrefix(l, "@") {
			inbound.Listen = "0.0.0.0"
		}

		// parse stream settings into map
		var stream map[string]any
		if err := json.Unmarshal([]byte(inbound.StreamSettings), &stream); err != nil || stream == nil {
			stream = map[string]any{}
		}

		// ensure security tls (this is safe even if it was already set)
		stream["security"] = "tls"

		// ensure tlsSettings map
		var tlsMap map[string]any
		if existing, ok := stream["tlsSettings"]; ok {
			if m, ok2 := existing.(map[string]any); ok2 {
				tlsMap = m
			} else {
				// normalize if it's encoded differently
				if bs, err := json.Marshal(existing); err == nil {
					var tmp map[string]any
					if err2 := json.Unmarshal(bs, &tmp); err2 == nil {
						tlsMap = tmp
					}
				}
			}
		}
		if tlsMap == nil {
			tlsMap = map[string]any{}
		}

		// set required TLS entries
		tlsMap["alpn"] = []any{"h3", "h2"}
		tlsMap["fp"] = "random"
		tlsMap["fingerprint"] = "random"

		stream["tlsSettings"] = tlsMap

		// write back updated stream settings
		if b, err := json.Marshal(stream); err == nil {
			inbound.StreamSettings = string(b)
		}
	}
}