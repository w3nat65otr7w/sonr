package register

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/onsonr/sonr/internal/database/sessions"
)

type CreateProfileData struct {
	TurnstileSiteKey string
	FirstNumber      int
	LastNumber       int
}

type RegisterPasskeyData struct {
	Address       string
	Handle        string
	Name          string
	Challenge     string
	CreationBlock string
}

// Helper function to shorten address
func shortenAddress(address string) string {
	if len(address) <= 20 {
		return address
	}
	return address[:16] + "..." + address[len(address)-4:]
}

func (d CreateProfileData) IsHumanLabel() string {
	return fmt.Sprintf("What is %d + %d?", d.FirstNumber, d.LastNumber)
}

func extractCredentialDescriptor(jsonString string) (*sessions.Credential, error) {
	cred := &sessions.Credential{}
	// Unmarshal the credential JSON
	if err := json.Unmarshal([]byte(jsonString), cred); err != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid credential format: %v", err))
	}

	// Validate required fields
	if cred.ID == "" || cred.RawID == "" {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "missing credential ID")
	}
	if cred.Type != "public-key" {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid credential type")
	}
	if cred.Response.AttestationObject == "" || cred.Response.ClientDataJSON == "" {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "missing attestation data")
	}

	// Log detailed credential information
	fmt.Printf("Credential Details:\n"+
		"ID: %s\n"+
		"Raw ID: %s\n"+
		"Type: %s\n"+
		"Authenticator Attachment: %s\n"+
		"Transports: %v\n"+
		"Attestation Object Size: %d bytes\n"+
		"Client Data Size: %d bytes\n",
		cred.ID,
		cred.RawID,
		cred.Type,
		cred.AuthenticatorAttachment,
		cred.Transports,
	)
	return cred, nil
}
