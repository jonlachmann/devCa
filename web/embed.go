// Package web embeds the built Svelte UI (web/dist/ui). Run scripts/build.sh
// (or `npm run build` in web/) to build it.
package web

import (
	"embed"
	"io/fs"
	"testing/fstest"
)

//go:embed all:dist
var dist embed.FS

const placeholder = `<!doctype html><meta charset="utf-8"><title>DevCA</title>
<p style="font-family:system-ui;margin:3rem">This DevCA binary was built without its web UI.
Run <code>scripts/build.sh</code>. The CLI works without it.</p>`

// Dist returns the UI files, or a one-page placeholder if the UI wasn't built.
func Dist() fs.FS {
	if sub, err := fs.Sub(dist, "dist/ui"); err == nil {
		if _, err := fs.Stat(sub, "index.html"); err == nil {
			return sub
		}
	}
	return fstest.MapFS{"index.html": {Data: []byte(placeholder)}}
}
