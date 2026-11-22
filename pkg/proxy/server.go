package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ER-brocode/nexus-git-registry/pkg/gitstorage"
	"github.com/ER-brocode/nexus-git-registry/pkg/oci"
)

var (
	manifestRegex = regexp.MustCompile(`^/v2/([a-z0-9._/-]+)/manifests/([a-zA-Z0-9_.:-]+)$`)
	blobsRegex    = regexp.MustCompile(`^/v2/([a-z0-9._/-]+)/blobs/(sha256:[a-f0-9]{64})$`)
	uploadsRegex  = regexp.MustCompile(`^/v2/([a-z0-9._/-]+)/blobs/uploads/?$`)
	uploadIDRegex = regexp.MustCompile(`^/v2/([a-z0-9._/-]+)/blobs/uploads/([a-zA-Z0-9_-]+)$`)
	tagsRegex     = regexp.MustCompile(`^/v2/([a-z0-9._/-]+)/tags/list$`)
)

// Server implements full Docker / OCI Registry v2 Specification.
type Server struct {
	blobStore   *oci.BlobStore
	gitRegistry *gitstorage.GitRegistry
	auth        *Authenticator
	cdcIndex    *oci.DeduplicationIndex
	p2pPeers    []string
	requireAuth bool
}

// Config defines Registry Server startup parameters.
type Config struct {
	BaseDir      string
	GitDir       string
	Realm        string
	Service      string
	P2PPeers     []string
	RequireAuth  bool
}

// NewServer initializes the complete OCI v2 distribution proxy.
func NewServer(cfg Config) (*Server, error) {
	blobStore, err := oci.NewBlobStore(cfg.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to init blob store: %w", err)
	}

	gitReg, err := gitstorage.NewGitRegistry(cfg.GitDir)
	if err != nil {
		return nil, fmt.Errorf("failed to init git registry: %w", err)
	}

	auth := NewAuthenticator(cfg.Realm, cfg.Service)

	return &Server{
		blobStore:   blobStore,
		gitRegistry: gitReg,
		auth:        auth,
		cdcIndex:    oci.NewDeduplicationIndex(),
		p2pPeers:    cfg.P2PPeers,
		requireAuth: cfg.RequireAuth,
	}, nil
}

// BlobStore returns the internal content-addressable blob storage engine.
func (s *Server) BlobStore() *oci.BlobStore {
	return s.blobStore
}

// GitRegistry returns the internal Git-native manifest storage engine.
func (s *Server) GitRegistry() *gitstorage.GitRegistry {
	return s.gitRegistry
}

// Authenticator returns the auth module.
func (s *Server) Authenticator() *Authenticator {
	return s.auth
}

// DeduplicationIndex returns FastCDC statistics tracker.
func (s *Server) DeduplicationIndex() *oci.DeduplicationIndex {
	return s.cdcIndex
}

// ServeHTTP routes incoming registry requests according to Docker Registry v2 spec.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add OCI standard header
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	path := r.URL.Path

	// 1. Version Check: GET /v2/
	if path == "/v2" || path == "/v2/" {
		s.handleVersionCheck(w, r)
		return
	}

	// 2. Auth Token Endpoint: GET /v2/token
	if path == "/v2/token" {
		s.handleTokenIssue(w, r)
		return
	}

	// 3. FastCDC Deduplication Metrics: GET /v2/_nexus/metrics
	if path == "/v2/_nexus/metrics" {
		if !s.authorizeRequest(w, r, "", "") {
			return
		}
		s.handleMetrics(w, r)
		return
	}

	// 4. Manifest Handlers
	if matches := manifestRegex.FindStringSubmatch(path); len(matches) == 3 {
		repo := matches[1]
		if !s.authorizeRequest(w, r, repo, requiredAction(r.Method)) {
			return
		}
		reference := matches[2]
		s.handleManifests(w, r, repo, reference)
		return
	}

	// 5. Blob Existence / Download: GET/HEAD /v2/<repo>/blobs/<digest>
	if matches := blobsRegex.FindStringSubmatch(path); len(matches) == 3 {
		repo := matches[1]
		if !s.authorizeRequest(w, r, repo, requiredAction(r.Method)) {
			return
		}
		digest := matches[2]
		s.handleBlobs(w, r, repo, digest)
		return
	}

	// 6. Blob Upload Session Initiation: POST /v2/<repo>/blobs/uploads/
	if matches := uploadsRegex.FindStringSubmatch(path); len(matches) == 2 {
		repo := matches[1]
		if !s.authorizeRequest(w, r, repo, requiredAction(r.Method)) {
			return
		}
		s.handleUploadStart(w, r, repo)
		return
	}

	// 7. Blob Upload Chunk / Commit: PATCH, PUT, DELETE /v2/<repo>/blobs/uploads/<uuid>
	if matches := uploadIDRegex.FindStringSubmatch(path); len(matches) == 3 {
		repo := matches[1]
		if !s.authorizeRequest(w, r, repo, requiredAction(r.Method)) {
			return
		}
		sessionID := matches[2]
		s.handleUploadSession(w, r, repo, sessionID)
		return
	}

	// 8. Tag Listing: GET /v2/<repo>/tags/list
	if matches := tagsRegex.FindStringSubmatch(path); len(matches) == 2 {
		repo := matches[1]
		if !s.authorizeRequest(w, r, repo, requiredAction(r.Method)) {
			return
		}
		s.handleTagList(w, r, repo)
		return
	}

	http.NotFound(w, r)
}

// requiredAction maps read-only registry requests to pull scope and mutations to push scope.
func requiredAction(method string) string {
	if method == http.MethodGet || method == http.MethodHead {
		return "pull"
	}
	return "push"
}

// authorizeRequest enforces Config.RequireAuth and repository-scoped token permissions.
// The version and token endpoints remain available for OCI discovery and token exchange.
func (s *Server) authorizeRequest(w http.ResponseWriter, r *http.Request, repo, action string) bool {
	if !s.requireAuth {
		return true
	}

	payload, err := s.auth.AuthenticateRequest(r)
	if err != nil {
		s.auth.WriteAuthChallenge(w, repo, action)
		return false
	}

	// Metrics are protected by authentication but do not belong to a repository scope.
	if repo == "" {
		return true
	}

	for _, grant := range payload.Access {
		if grant.Type != "repository" || (grant.Name != repo && grant.Name != "*") {
			continue
		}
		for _, allowed := range grant.Actions {
			if allowed == "*" || allowed == action {
				return true
			}
		}
	}

	s.writeError(w, http.StatusForbidden, "DENIED", "requested access to the resource is denied")
	return false
}

func (s *Server) handleVersionCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{}`))
}

func (s *Server) handleTokenIssue(w http.ResponseWriter, r *http.Request) {
	user, pass, hasAuth := r.BasicAuth()
	if !hasAuth || !s.auth.VerifyBasicAuth(user, pass) {
		s.auth.WriteAuthChallenge(w, "", "")
		return
	}

	scope := r.URL.Query().Get("scope")
	var access []ResourceAccess
	if scope != "" {
		parts := strings.Split(scope, ":")
		if len(parts) >= 3 {
			actions := strings.Split(parts[2], ",")
			access = append(access, ResourceAccess{
				Type:    parts[0],
				Name:    parts[1],
				Actions: actions,
			})
		}
	} else {
		access = append(access, ResourceAccess{
			Type:    "repository",
			Name:    "*",
			Actions: []string{"pull", "push"},
		})
	}

	token, err := s.auth.IssueToken(user, access)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":        token,
		"access_token": token,
		"expires_in":   7200,
		"issued_at":    timeNowISO(),
	})
}

func (s *Server) handleManifests(w http.ResponseWriter, r *http.Request, repo, reference string) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		data, digest, err := s.gitRegistry.GetManifest(repo, reference)
		if err != nil {
			s.writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", fmt.Sprintf("manifest %s not found", reference))
			return
		}

		w.Header().Set("Content-Type", oci.MediaTypeImageManifest)
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Etag", fmt.Sprintf("\"%s\"", digest))
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)

		if r.Method == http.MethodGet {
			w.Write(data)
		}

	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", "failed to read body")
			return
		}
		defer r.Body.Close()

		mediaType := r.Header.Get("Content-Type")
		if mediaType == "" {
			mediaType = oci.MediaTypeImageManifest
		}

		rec, err := s.gitRegistry.PutManifest(repo, reference, body, mediaType)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "MANIFEST_INVALID", err.Error())
			return
		}

		w.Header().Set("Docker-Content-Digest", rec.Digest)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", repo, rec.Digest))
		w.WriteHeader(http.StatusCreated)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBlobs(w http.ResponseWriter, r *http.Request, repo, digest string) {
	switch r.Method {
	case http.MethodHead:
		size, err := s.blobStore.Stat(digest)
		if err != nil {
			s.writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		rc, size, err := s.blobStore.Open(digest)
		if err != nil {
			s.writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
			return
		}
		defer rc.Close()

		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		io.Copy(w, rc)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUploadStart(w http.ResponseWriter, r *http.Request, repo string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	sessionBytes := make([]byte, 16)
	_, _ = rand.Read(sessionBytes)
	sessionID := hex.EncodeToString(sessionBytes)

	// Single-step monolithic upload via ?digest=sha256:...
	digestQuery := r.URL.Query().Get("digest")
	if digestQuery != "" && r.ContentLength > 0 {
		readData, err := io.ReadAll(r.Body)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		computed, _, err := s.blobStore.Put(digestQuery, strings.NewReader(string(readData)))
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "DIGEST_INVALID", err.Error())
			return
		}

		// FastCDC chunk deduplication analysis
		fastCDC := oci.NewFastCDC(16*1024, 64*1024, 256*1024)
		chunks := fastCDC.ChunkBuffer(readData)
		for _, c := range chunks {
			s.cdcIndex.RecordChunk(c)
		}

		w.Header().Set("Docker-Content-Digest", computed)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, computed))
		w.WriteHeader(http.StatusCreated)
		return
	}

	_, err := s.blobStore.StartUpload(repo, sessionID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "UNKNOWN", err.Error())
		return
	}

	location := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, sessionID)
	w.Header().Set("Location", location)
	w.Header().Set("Range", "0-0")
	w.Header().Set("Docker-Upload-UUID", sessionID)
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleUploadSession(w http.ResponseWriter, r *http.Request, repo, sessionID string) {
	switch r.Method {
	case http.MethodPatch:
		offset, err := s.blobStore.WriteChunk(sessionID, r.Body)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		defer r.Body.Close()

		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, sessionID))
		w.Header().Set("Range", fmt.Sprintf("0-%d", offset))
		w.Header().Set("Docker-Upload-UUID", sessionID)
		w.WriteHeader(http.StatusAccepted)

	case http.MethodPut:
		expectedDigest := r.URL.Query().Get("digest")
		if expectedDigest == "" {
			s.writeError(w, http.StatusBadRequest, "DIGEST_INVALID", "missing digest query parameter")
			return
		}

		// Optional trailing chunk sent in PUT body
		if r.ContentLength > 0 {
			_, err := s.blobStore.WriteChunk(sessionID, r.Body)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", err.Error())
				return
			}
			defer r.Body.Close()
		}

		digest, _, err := s.blobStore.FinishUpload(sessionID, expectedDigest)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "DIGEST_INVALID", err.Error())
			return
		}

		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, digest))
		w.WriteHeader(http.StatusCreated)

	case http.MethodDelete:
		_ = s.blobStore.CancelUpload(sessionID)
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTagList(w http.ResponseWriter, r *http.Request, repo string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	tags, err := s.gitRegistry.ListTags(repo)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "UNKNOWN", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name": repo,
		"tags": tags,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	raw, unique, savings := s.cdcIndex.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"fastcdc_total_bytes":      raw,
		"fastcdc_unique_bytes":     unique,
		"fastcdc_savings_pct":      savings,
		"ed25519_signer_public_key": s.gitRegistry.PublicKeyHex(),
		"p2p_mesh_peers":           s.p2pPeers,
	})
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"errors": []map[string]string{
			{
				"code":    code,
				"message": message,
			},
		},
	})
}

func timeNowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}
