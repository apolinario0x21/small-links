// Package safebrowsing consulta a Google Safe Browsing API (Lookup v4)
// para identificar URLs maliciosas antes de encurtá-las.
package safebrowsing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	defaultEndpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
	// requestTimeout mantém a verificação curta: nunca deve travar o
	// encurtamento (o caminho de erro é fail-open).
	requestTimeout = 2 * time.Second
)

// threatTypes são os tipos de ameaça consultados.
var threatTypes = []string{
	"MALWARE",
	"SOCIAL_ENGINEERING",
	"UNWANTED_SOFTWARE",
	"POTENTIALLY_HARMFUL_APPLICATION",
}

// Client consulta a Safe Browsing API.
type Client struct {
	apiKey     string
	endpoint   string
	httpClient *http.Client
}

func New(apiKey string) *Client {
	return &Client{
		apiKey:     apiKey,
		endpoint:   defaultEndpoint,
		httpClient: &http.Client{Timeout: requestTimeout},
	}
}

type findRequest struct {
	Client     clientInfo `json:"client"`
	ThreatInfo threatInfo `json:"threatInfo"`
}

type clientInfo struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type threatInfo struct {
	ThreatTypes      []string      `json:"threatTypes"`
	PlatformTypes    []string      `json:"platformTypes"`
	ThreatEntryTypes []string      `json:"threatEntryTypes"`
	ThreatEntries    []threatEntry `json:"threatEntries"`
}

type threatEntry struct {
	URL string `json:"url"`
}

type findResponse struct {
	Matches []json.RawMessage `json:"matches"`
}

// Malicious retorna true se a URL casar com alguma ameaça conhecida.
// Um erro não-nil indica que a própria verificação falhou (o chamador
// decide o fail-open); nesse caso o bool é sempre false.
func (c *Client) Malicious(ctx context.Context, rawURL string) (bool, error) {
	payload, err := json.Marshal(findRequest{
		Client: clientInfo{ClientID: "small-links", ClientVersion: "1.0"},
		ThreatInfo: threatInfo{
			ThreatTypes:      threatTypes,
			PlatformTypes:    []string{"ANY_PLATFORM"},
			ThreatEntryTypes: []string{"URL"},
			ThreatEntries:    []threatEntry{{URL: rawURL}},
		},
	})
	if err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	endpoint := c.endpoint + "?key=" + url.QueryEscape(c.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("safe browsing API returned status %d", resp.StatusCode)
	}

	var out findResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}

	return len(out.Matches) > 0, nil
}
