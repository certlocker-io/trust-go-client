// Read-only live smoke. Credentials are inherited through the environment and never printed.
package main

import (
	"context"
	"encoding/json"
	trust "github.com/Darren-Certlocker/trust-go-client"
	"os"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b := trust.NewBuilder().URL(os.Getenv("TRUST_URL")).APIToken(os.Getenv("CERTLOCKER_TOKEN")).LegacyAPI(os.Getenv("CERTLOCKER_API_MODE") == "legacy")
	if account := os.Getenv("CERTLOCKER_ACCOUNT_ID"); account != "" {
		b.AccountID(account)
	}
	c, err := b.Build(ctx)
	if err != nil {
		fail()
	}
	defer c.Close()
	meta, err := c.GetSecret(ctx, os.Getenv("TRUST_SECRET_ID"))
	if err != nil {
		fail()
	}
	var record map[string]any
	if json.Unmarshal([]byte(meta), &record) != nil || record["id"] != os.Getenv("TRUST_SECRET_ID") {
		fail()
	}
	value, err := c.FetchSecret(ctx, os.Getenv("TRUST_SECRET_ID"))
	if err != nil || value != os.Getenv("TRUST_EXPECTED_VALUE") {
		fail()
	}
	tok, err := c.GetToken(ctx, os.Getenv("CERTLOCKER_TOKEN"))
	if err != nil {
		fail()
	}
	var token map[string]any
	if json.Unmarshal([]byte(tok), &token) != nil || token["id"] != os.Getenv("CERTLOCKER_TOKEN") {
		fail()
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]bool{"secret_metadata": true, "secret_value_matches": true, "token_metadata": true})
}
func fail() {
	_, _ = os.Stderr.WriteString("Trust smoke failed; credential and response details suppressed\n")
	os.Exit(1)
}
