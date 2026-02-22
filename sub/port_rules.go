package sub

import (
	"encoding/json"

	"github.com/kirden31/3x-ui/database/model"
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

		// parse stream settings into map
		var stream map[string]any
		if err := json.Unmarshal([]byte(inbound.StreamSettings), &stream); err != nil || stream == nil {
			stream = map[string]any{}
		}

		// ensure security tls (this is safe even if it was already set)
		stream["security"] = "tls"

		// ensure tlsSettings exists and is a map
		tlsMap := map[string]any{}
		if existing, ok := stream["tlsSettings"]; ok {
			if m, ok2 := existing.(map[string]any); ok2 {
				tlsMap = m
			} else {
				// try to normalize
				if bs, err := json.Marshal(existing); err == nil {
					var tmp map[string]any
					if err2 := json.Unmarshal(bs, &tmp); err2 == nil {
						tlsMap = tmp
					}
				}
			}
		}

		// set or override only the requested fields
		tlsMap["alpn"] = []any{"h3", "h2"}
		tlsMap["fingerprint"] = "random"

		stream["tlsSettings"] = tlsMap

		// write back updated stream settings
		if b, err := json.Marshal(stream); err == nil {
			inbound.StreamSettings = string(b)
		}
	}
}