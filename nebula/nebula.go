package nebula

import (
	"embed"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
)

//go:embed assets
var embeddedFiles embed.FS

// UseAssets is a middleware that serves static files from the embedded assets
func UseAssets(e *echo.Echo) echo.HandlerFunc {
	embFs := http.FS(os.DirFS("assets"))
	assets := http.FileServer(embFs)
	return echo.WrapHandler(assets)
}
