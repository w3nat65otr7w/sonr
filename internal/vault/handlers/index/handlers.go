package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	session "github.com/onsonr/sonr/internal/vault/session"
)

func Handler(c echo.Context) error {
	// TODO: Create views
	if isInitial(c) {
		// return response.TemplEcho(c, index.InitialView())
	}
	// TODO: Add authorization check
	if isExpired(c) {
		// return response.TemplEcho(c, index.ReturningView())
	}
	return c.Render(http.StatusOK, "index.templ", nil)
}

// ╭─────────────────────────────────────────────────────────╮
// │                    Utility Functions                    │
// ╰─────────────────────────────────────────────────────────╯

// Initial users have no authorization, user handle, or vault address
func isInitial(c echo.Context) bool {
	noAuth := !session.HasAuthorization(c)
	noUserHandle := !session.HasUserHandle(c)
	noVaultAddress := !session.HasVaultAddress(c)
	return noUserHandle && noVaultAddress && noAuth
}

// Expired users have either a user handle or vault address
func isExpired(c echo.Context) bool {
	noAuth := !session.HasAuthorization(c)
	hasUserHandle := session.HasUserHandle(c)
	hasVaultAddress := session.HasVaultAddress(c)
	return noAuth && hasUserHandle || noAuth && hasVaultAddress
}

// Returning users have a valid authorization, and either a user handle or vault address
func isReturning(c echo.Context) bool {
	hasAuth := session.HasAuthorization(c)
	hasUserHandle := session.HasUserHandle(c)
	hasVaultAddress := session.HasVaultAddress(c)
	return hasAuth && (hasUserHandle || hasVaultAddress)
}
