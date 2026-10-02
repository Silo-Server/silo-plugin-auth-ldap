package main

import (
	"encoding/json"
	"io/fs"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
)

func loadTestManifest(t *testing.T) *pluginv1.PluginManifest {
	t.Helper()
	m, err := manifest.Load(manifestJSON)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if err := manifest.Validate(m); err != nil {
		t.Fatalf("validate manifest: %v", err)
	}
	return m
}

// Silo keys installations by this ID, so changing it turns an upgrade into a
// separate plugin. It pairs with silo.auth.oidc.
func TestManifestPluginID(t *testing.T) {
	if got := loadTestManifest(t).GetPluginId(); got != "silo.auth.ldap" {
		t.Fatalf("plugin_id = %q, want silo.auth.ldap", got)
	}
}

func TestManifestDeclaresAuthProvider(t *testing.T) {
	m := loadTestManifest(t)
	var auth, routes *pluginv1.CapabilityDescriptor
	for _, c := range m.GetCapabilities() {
		switch c.GetType() {
		case "auth_provider.v1":
			auth = c
		case "http_routes.v1":
			routes = c
		}
	}
	if auth == nil || routes == nil {
		t.Fatal("manifest needs auth_provider.v1 and http_routes.v1 capabilities")
	}
	if len(auth.GetAuthModes()) != 1 || auth.GetAuthModes()[0] != manifest.AuthModePassword {
		t.Fatalf("auth_modes = %v, want [password]", auth.GetAuthModes())
	}
	if !manifest.AuthProviderSupportsConnectionTest(auth) {
		t.Fatal("capability must advertise connection_test")
	}
}

func TestManifestServesPublicIcon(t *testing.T) {
	m := loadTestManifest(t)
	public := false
	for _, r := range m.GetHttpRoutes() {
		if r.GetMethod() == "GET" && r.GetPath() == "/assets/*" && r.GetAccess() == "public" {
			public = true
		}
	}
	if !public {
		t.Fatal("the icon route must be a public GET /assets/* route")
	}
	icon := defaultValue(t, m, "icon_url_path", "value")
	if _, err := fs.Stat(embeddedAssets, "assets/"+icon); err != nil {
		t.Fatalf("default icon %q is not embedded: %v", icon, err)
	}
	if defaultValue(t, m, "display_name", "value") == "" {
		t.Fatal("display_name needs a default label")
	}
}

func TestManifestMarksSecrets(t *testing.T) {
	m := loadTestManifest(t)
	for _, schema := range m.GetGlobalConfigSchema() {
		var parsed struct {
			Properties map[string]map[string]any `json:"properties"`
		}
		if err := json.Unmarshal([]byte(schema.GetJsonSchema()), &parsed); err != nil {
			t.Fatalf("%s json_schema: %v", schema.GetKey(), err)
		}
		for _, field := range schema.GetAdminForm().GetFields() {
			secret := field.GetKey() == "bind_password"
			if secret != field.GetSecret() {
				t.Errorf("%s.%s secret=%v", schema.GetKey(), field.GetKey(), field.GetSecret())
			}
			if secret && parsed.Properties[field.GetKey()]["writeOnly"] != true {
				t.Errorf("%s.%s must be writeOnly in json_schema", schema.GetKey(), field.GetKey())
			}
		}
	}
}

func defaultValue(t *testing.T, m *pluginv1.PluginManifest, key, field string) string {
	t.Helper()
	for _, schema := range m.GetGlobalConfigSchema() {
		if schema.GetKey() != key {
			continue
		}
		for _, f := range schema.GetAdminForm().GetFields() {
			if f.GetKey() == field {
				return f.GetDefaultValue().GetStringValue()
			}
		}
	}
	t.Fatalf("no %s.%s field in global_config_schema", key, field)
	return ""
}
