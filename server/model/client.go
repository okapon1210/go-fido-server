package model

type CollectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	TopOrigin   string `json:"topOrigin,omitempty"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}
