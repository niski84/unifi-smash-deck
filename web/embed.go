package web

import "embed"

// FS holds all files under web/unifideck/ embedded into the binary at compile time.
//go:embed unifideck
var FS embed.FS
