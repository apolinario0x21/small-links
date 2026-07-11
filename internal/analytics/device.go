package analytics

import "github.com/mileusna/useragent"

const maxFieldLen = 20 // limite das colunas device/os (VARCHAR(20))

// parseDevice classifica o user-agent em device (mobile/tablet/desktop/bot),
// sistema operacional e flag de bot. Campos vazios viram NULL no banco.
func parseDevice(uaString string) (device, os string, isBot bool) {
	if uaString == "" {
		return "", "", false
	}

	ua := useragent.Parse(uaString)

	switch {
	case ua.Bot:
		device, isBot = "bot", true
	case ua.Mobile:
		device = "mobile"
	case ua.Tablet:
		device = "tablet"
	case ua.Desktop:
		device = "desktop"
	}

	os = ua.OS
	if len(os) > maxFieldLen {
		os = os[:maxFieldLen]
	}

	return device, os, isBot
}
