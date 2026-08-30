// Package geoip resolves a public IP to a country via a free external API
// (ip-api.com). No API key, no local database — trades a small amount of
// external exposure of enrolled peers' public IPs for zero ops overhead.
package geoip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: 3 * time.Second}

type response struct {
	Status  string `json:"status"`
	Country string `json:"country"`
}

// Lookup returns the country name for a public IP, or an error if the
// lookup fails or the IP can't be geolocated (private/reserved ranges).
func Lookup(ip string) (string, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country", ip)
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("geoip lookup: %w", err)
	}
	defer resp.Body.Close()

	var r response
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("geoip decode: %w", err)
	}
	if r.Status != "success" {
		return "", fmt.Errorf("geoip lookup failed for %s", ip)
	}
	return r.Country, nil
}
