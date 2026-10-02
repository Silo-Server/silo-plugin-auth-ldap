// Command plugin is Silo's first-party LDAP auth provider.
package main

import (
	"embed"
	"io/fs"
	"os"

	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/hashicorp/go-hclog"

	"github.com/Silo-Server/silo-plugin-auth-ldap/ldapauth"
)

// version is set at build time via -ldflags "-X main.version=...".
var version string

//go:embed manifest.json
var manifestJSON []byte

//go:embed assets
var embeddedAssets embed.FS

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "auth-ldap",
		Output:     os.Stderr,
		Level:      hclog.Info,
		JSONFormat: true,
	})
	provider := ldapauth.New(logger)
	assets, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		panic(err)
	}

	// ServeManifestWithOptions stamps the version and the binary's sha256
	// into the embedded manifest and answers `plugin manifest`.
	runtime.ServeManifestWithOptions(manifestJSON, version,
		runtime.CapabilityServers{
			AuthProvider: provider,
			HttpRoutes:   ldapauth.NewAssetRoutes(assets),
		},
		runtime.WithAuthProviderChecks(provider),
		runtime.WithConfigure(provider.Configure),
	)
}
