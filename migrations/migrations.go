// Package migrations embute os arquivos SQL versionados do schema.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
