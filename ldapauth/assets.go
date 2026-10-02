package ldapauth

import (
	"context"
	"io/fs"
	"net/http"
	"path"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// AssetRoutes serves embedded files under the public GET /assets/* route,
// such as the login-button icon. Catalog installs ship only the binary, so
// the files are compiled in.
type AssetRoutes struct {
	pluginv1.UnimplementedHttpRoutesServer
	files fs.FS
}

var _ pluginv1.HttpRoutesServer = (*AssetRoutes)(nil)

// NewAssetRoutes serves files from fsys; a request for /assets/x reads x.
func NewAssetRoutes(fsys fs.FS) *AssetRoutes { return &AssetRoutes{files: fsys} }

var contentTypes = map[string]string{
	".svg":  "image/svg+xml",
	".png":  "image/png",
	".webp": "image/webp",
}

func (a *AssetRoutes) Handle(_ context.Context, req *pluginv1.HandleHTTPRequest) (*pluginv1.HandleHTTPResponse, error) {
	if req.GetMethod() != http.MethodGet && req.GetMethod() != http.MethodHead {
		return textResponse(http.StatusMethodNotAllowed, "method not allowed"), nil
	}
	name, ok := strings.CutPrefix(req.GetPath(), "/assets/")
	if !ok || name == "" || strings.Contains(name, "\\") || path.Clean("/"+name) != "/"+name {
		return textResponse(http.StatusNotFound, "not found"), nil
	}
	contentType, known := contentTypes[strings.ToLower(path.Ext(name))]
	if !known {
		return textResponse(http.StatusNotFound, "not found"), nil
	}
	body, err := fs.ReadFile(a.files, name)
	if err != nil {
		return textResponse(http.StatusNotFound, "not found"), nil
	}
	if req.GetMethod() == http.MethodHead {
		body = nil
	}
	return &pluginv1.HandleHTTPResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type":            contentType,
			"Cache-Control":           "public, max-age=86400",
			"X-Content-Type-Options":  "nosniff",
			"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
		},
		Body: body,
	}, nil
}

func textResponse(status int, text string) *pluginv1.HandleHTTPResponse {
	return &pluginv1.HandleHTTPResponse{
		StatusCode: int32(status),
		Headers:    map[string]string{"Content-Type": "text/plain; charset=utf-8"},
		Body:       []byte(text),
	}
}
