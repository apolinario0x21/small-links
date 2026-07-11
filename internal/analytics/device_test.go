package analytics

import "testing"

func TestParseDeviceRealUserAgents(t *testing.T) {
	cases := []struct {
		name   string
		ua     string
		device string
		isBot  bool
	}{
		{
			name:   "iPhone",
			ua:     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			device: "mobile",
		},
		{
			name:   "Android",
			ua:     "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.113 Mobile Safari/537.36",
			device: "mobile",
		},
		{
			name:   "iPad",
			ua:     "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			device: "tablet",
		},
		{
			name:   "Desktop Windows",
			ua:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
			device: "desktop",
		},
		{
			name:   "Desktop macOS Firefox",
			ua:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
			device: "desktop",
		},
		{
			name:   "Googlebot",
			ua:     "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			device: "bot",
			isBot:  true,
		},
		{
			name:   "curl",
			ua:     "curl/8.5.0",
			device: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device, os, isBot := parseDevice(tc.ua)
			if device != tc.device {
				t.Errorf("device = %q, want %q", device, tc.device)
			}
			if isBot != tc.isBot {
				t.Errorf("isBot = %v, want %v", isBot, tc.isBot)
			}
			if len(os) > maxFieldLen {
				t.Errorf("os %q excede %d chars", os, maxFieldLen)
			}
		})
	}
}

func TestParseDeviceEmptyUA(t *testing.T) {
	device, os, isBot := parseDevice("")
	if device != "" || os != "" || isBot {
		t.Errorf("UA vazio deve retornar campos vazios, got %q/%q/%v", device, os, isBot)
	}
}
