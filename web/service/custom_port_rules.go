package service

import (
    "encoding/json"
    "os"
    "strings"

    "github.com/kirden31/3x-ui/v2/database/model"
)

func normalizeInboundForDB(inb *model.Inbound) {
    if inb == nil {
        return
    }

    // port
    if inb.Port >= 10000 && inb.Port <= 11000 {
        inb.Port = 443
    }

    // listen
    l := strings.TrimSpace(inb.Listen)
    if l == "" || l == "127.0.0.1" || l == "localhost" || strings.HasPrefix(l, "@") {
        inb.Listen = "0.0.0.0"
    }

    // streamSettings
    var ss map[string]any
    if err := json.Unmarshal([]byte(inb.StreamSettings), &ss); err != nil || ss == nil {
        ss = map[string]any{}
    }

    ss["security"] = "tls"

    tlsMap := map[string]any{}
    if existing, ok := ss["tlsSettings"]; ok {
        if m, ok2 := existing.(map[string]any); ok2 {
            tlsMap = m
        }
    }

    tlsMap["alpn"] = []any{"h3","h2"}
    tlsMap["fingerprint"] = "random"

    settingsMap := map[string]any{}
    if existingSettings, ok := tlsMap["settings"].(map[string]any); ok {
        settingsMap = existingSettings
    }
    settingsMap["fingerprint"] = "random"
    tlsMap["settings"] = settingsMap

    ss["tlsSettings"] = tlsMap

    if b, err := json.Marshal(ss); err == nil {
        inb.StreamSettings = string(b)
    }
}