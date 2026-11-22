package tests

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ER-brocode/nexus-git-registry/pkg/oci"
	"github.com/ER-brocode/nexus-git-registry/pkg/proxy"
)

func setupTestServer(t *testing.T) (*proxy.Server, func()) {
	return setupTestServerWithAuth(t, false)
}

func setupTestServerWithAuth(t *testing.T, requireAuth bool) (*proxy.Server, func()) {
	tmpDir, err := os.MkdirTemp("", "nexus-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	blobDir := filepath.Join(tmpDir, "blobs")
	gitDir := filepath.Join(tmpDir, "git-meta")

	cfg := proxy.Config{
		BaseDir:     blobDir,
		GitDir:      gitDir,
		Realm:       "http://localhost:5000/v2/token",
		Service:     "nexus-git-registry",
		P2PPeers:    []string{"10.0.0.1:5000", "10.0.0.2:5000"},
		RequireAuth: requireAuth,
	}

	server, err := proxy.NewServer(cfg)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to instantiate server: %v", err)
	}
	server.Authenticator().AddUser("test-user", "test-password")

	teardown := func() {
		os.RemoveAll(tmpDir)
	}
	return server, teardown
}

func TestV2Ping(t *testing.T) {
	server, teardown := setupTestServer(t)
	defer teardown()

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /v2/, got %d", rec.Code)
	}
	if rec.Header().Get("Docker-Distribution-Api-Version") != "registry/2.0" {
		t.Errorf("missing or invalid Docker-Distribution-Api-Version header")
	}
}

func TestBlobUploadAndDownload(t *testing.T) {
	server, teardown := setupTestServer(t)
	defer teardown()

	repo := "library/alpine"
	payload := []byte("Nexus Git-Native Artifact Registry Container Layer Payload 0xDEADBEEF")
	h := sha256.Sum256(payload)
	expectedDigest := "sha256:" + hex.EncodeToString(h[:])

	// 1. Monolithic Upload
	reqUpload := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v2/%s/blobs/uploads/?digest=%s", repo, expectedDigest), bytes.NewReader(payload))
	reqUpload.Header.Set("Content-Type", "application/octet-stream")
	recUpload := httptest.NewRecorder()
	server.ServeHTTP(recUpload, reqUpload)

	if recUpload.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on monolithic blob upload, got %d: %s", recUpload.Code, recUpload.Body.String())
	}
	if recUpload.Header().Get("Docker-Content-Digest") != expectedDigest {
		t.Errorf("digest mismatch: expected %s, got %s", expectedDigest, recUpload.Header().Get("Docker-Content-Digest"))
	}

	// 2. Blob HEAD check
	reqHead := httptest.NewRequest(http.MethodHead, fmt.Sprintf("/v2/%s/blobs/%s", repo, expectedDigest), nil)
	recHead := httptest.NewRecorder()
	server.ServeHTTP(recHead, reqHead)

	if recHead.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for HEAD blob, got %d", recHead.Code)
	}

	// 3. Blob GET download
	reqGet := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/v2/%s/blobs/%s", repo, expectedDigest), nil)
	recGet := httptest.NewRecorder()
	server.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET blob, got %d", recGet.Code)
	}
	if !bytes.Equal(recGet.Body.Bytes(), payload) {
		t.Fatalf("retrieved blob data does not match uploaded payload")
	}
}

func TestResumableChunkedBlobUpload(t *testing.T) {
	server, teardown := setupTestServer(t)
	defer teardown()

	repo := "test/chunked"
	chunk1 := []byte("Part1-Alpha-")
	chunk2 := []byte("Part2-Beta-")
	chunk3 := []byte("Part3-Omega")
	fullPayload := append(append(chunk1, chunk2...), chunk3...)

	h := sha256.Sum256(fullPayload)
	expectedDigest := "sha256:" + hex.EncodeToString(h[:])

	// 1. Start Session
	reqStart := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v2/%s/blobs/uploads/", repo), nil)
	recStart := httptest.NewRecorder()
	server.ServeHTTP(recStart, reqStart)

	if recStart.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on upload start, got %d", recStart.Code)
	}
	uploadUUID := recStart.Header().Get("Docker-Upload-UUID")
	if uploadUUID == "" {
		t.Fatalf("missing Docker-Upload-UUID header")
	}

	// 2. Patch Chunk 1
	reqChunk1 := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uploadUUID), bytes.NewReader(chunk1))
	recChunk1 := httptest.NewRecorder()
	server.ServeHTTP(recChunk1, reqChunk1)
	if recChunk1.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for chunk 1, got %d", recChunk1.Code)
	}

	// 3. Patch Chunk 2
	reqChunk2 := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uploadUUID), bytes.NewReader(chunk2))
	recChunk2 := httptest.NewRecorder()
	server.ServeHTTP(recChunk2, reqChunk2)
	if recChunk2.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for chunk 2, got %d", recChunk2.Code)
	}

	// 4. Put Chunk 3 & Commit with ?digest=
	reqCommit := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/v2/%s/blobs/uploads/%s?digest=%s", repo, uploadUUID, expectedDigest), bytes.NewReader(chunk3))
	recCommit := httptest.NewRecorder()
	server.ServeHTTP(recCommit, reqCommit)

	if recCommit.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on upload finalize, got %d: %s", recCommit.Code, recCommit.Body.String())
	}

	// 5. Verify Content
	reqDownload := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/v2/%s/blobs/%s", repo, expectedDigest), nil)
	recDownload := httptest.NewRecorder()
	server.ServeHTTP(recDownload, reqDownload)

	if !bytes.Equal(recDownload.Body.Bytes(), fullPayload) {
		t.Errorf("chunked uploaded content corrupted")
	}
}

func TestManifestPushAndPull(t *testing.T) {
	server, teardown := setupTestServer(t)
	defer teardown()

	repo := "koushik4475/nexus-core"
	tag := "v1.0.0"

	// Mock valid config blob and layer blob
	cfgData := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	cfgDigest := oci.ComputeSHA256(cfgData)
	_, _, _ = server.BlobStore().Put(cfgDigest, bytes.NewReader(cfgData))

	layerData := []byte("rootfs-tarball-binary-layer-content")
	layerDigest := oci.ComputeSHA256(layerData)
	_, _, _ = server.BlobStore().Put(layerDigest, bytes.NewReader(layerData))

	manifestObj := oci.Manifest{
		SchemaVersion: 2,
		MediaType:     oci.MediaTypeImageManifest,
		Config: oci.Descriptor{
			MediaType: oci.MediaTypeImageConfig,
			Digest:    cfgDigest,
			Size:      int64(len(cfgData)),
		},
		Layers: []oci.Descriptor{
			{
				MediaType: oci.MediaTypeImageLayer,
				Digest:    layerDigest,
				Size:      int64(len(layerData)),
			},
		},
	}
	manifestBytes, err := json.Marshal(manifestObj)
	if err != nil {
		t.Fatalf("failed to serialize manifest: %v", err)
	}
	computedManifestDigest := oci.ComputeSHA256(manifestBytes)

	// 1. Put Manifest by Tag
	reqPut := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/v2/%s/manifests/%s", repo, tag), bytes.NewReader(manifestBytes))
	reqPut.Header.Set("Content-Type", oci.MediaTypeImageManifest)
	recPut := httptest.NewRecorder()
	server.ServeHTTP(recPut, reqPut)

	if recPut.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on manifest PUT, got %d: %s", recPut.Code, recPut.Body.String())
	}
	if recPut.Header().Get("Docker-Content-Digest") != computedManifestDigest {
		t.Errorf("expected digest %s, got %s", computedManifestDigest, recPut.Header().Get("Docker-Content-Digest"))
	}

	// 2. Get Manifest by Tag
	reqGetTag := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/v2/%s/manifests/%s", repo, tag), nil)
	recGetTag := httptest.NewRecorder()
	server.ServeHTTP(recGetTag, reqGetTag)

	if recGetTag.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on GET manifest by tag, got %d", recGetTag.Code)
	}
	if recGetTag.Header().Get("Docker-Content-Digest") != computedManifestDigest {
		t.Errorf("digest header mismatch on pull")
	}

	// 3. Get Manifest by Digest
	reqGetDigest := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/v2/%s/manifests/%s", repo, computedManifestDigest), nil)
	recGetDigest := httptest.NewRecorder()
	server.ServeHTTP(recGetDigest, reqGetDigest)

	if recGetDigest.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on GET manifest by digest, got %d", recGetDigest.Code)
	}

	// 4. List Tags
	reqTags := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/v2/%s/tags/list", repo), nil)
	recTags := httptest.NewRecorder()
	server.ServeHTTP(recTags, reqTags)

	if recTags.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on tags list, got %d", recTags.Code)
	}

	var tagsResp struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(recTags.Body.Bytes(), &tagsResp); err != nil {
		t.Fatalf("failed to decode tag response: %v", err)
	}
	if len(tagsResp.Tags) == 0 || tagsResp.Tags[0] != tag {
		t.Errorf("tag %s not found in listing: %+v", tag, tagsResp.Tags)
	}
}

func TestFastCDCDeduplication(t *testing.T) {
	cdc := oci.NewFastCDC(256, 1024, 4096)
	data1 := bytes.Repeat([]byte("Shared base layer operating system payload"), 200)
	data2 := bytes.Repeat([]byte("Shared base layer operating system payload"), 200)
	data2 = append(data2, []byte("Unique application patch")...)

	idx := oci.NewDeduplicationIndex()
	chunks1 := cdc.ChunkBuffer(data1)
	for _, c := range chunks1 {
		idx.RecordChunk(c)
	}

	chunks2 := cdc.ChunkBuffer(data2)
	for _, c := range chunks2 {
		idx.RecordChunk(c)
	}

	raw, unique, savings := idx.Stats()
	if raw <= unique {
		t.Errorf("expected deduplication savings, raw=%d, unique=%d", raw, unique)
	}
	if savings < 30.0 {
		t.Errorf("expected >30%% savings, got %.2f%%", savings)
	}
}

func TestEd25519SignatureVerification(t *testing.T) {
	server, teardown := setupTestServer(t)
	defer teardown()

	repo := "koushik4475/secure-artifact"
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	sigMeta, err := server.GitRegistry().SignManifest(repo, digest, "koushik4475")
	if err != nil {
		t.Fatalf("sign manifest failed: %v", err)
	}

	valid, err := server.GitRegistry().VerifySignature(digest, sigMeta)
	if err != nil || !valid {
		t.Fatalf("expected signature verification to succeed: valid=%v, err=%v", valid, err)
	}

	// Tampered digest test
	tamperedDigest := "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	tamperedValid, _ := server.GitRegistry().VerifySignature(tamperedDigest, sigMeta)
	if tamperedValid {
		t.Errorf("tampered digest signature must fail verification")
	}
}

func TestTokenAuthentication(t *testing.T) {
	server, teardown := setupTestServer(t)
	defer teardown()

	auth := server.Authenticator()

	// 1. Issue Token
	access := []proxy.ResourceAccess{
		{Type: "repository", Name: "koushik4475/nexus-git-registry", Actions: []string{"pull", "push"}},
	}
	token, err := auth.IssueToken("koushik4475", access)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	// 2. Validate Token
	payload, err := auth.ValidateToken(token)
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}
	if payload.Subject != "koushik4475" {
		t.Errorf("expected subject koushik4475, got %s", payload.Subject)
	}

	// 3. HTTP Request with Token
	req := httptest.NewRequest(http.MethodGet, "/v2/koushik4475/nexus-git-registry/tags/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK with bearer token, got %d", rec.Code)
	}
}

func TestTokenEndpointUsesCurrentIssuedAt(t *testing.T) {
	server, teardown := setupTestServer(t)
	defer teardown()

	req := httptest.NewRequest(http.MethodGet, "/v2/token", nil)
	req.SetBasicAuth("test-user", "test-password")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from token endpoint, got %d: %s", rec.Code, rec.Body.String())
	}

	var response struct {
		IssuedAt string `json:"issued_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	issuedAt, err := time.Parse(time.RFC3339, response.IssuedAt)
	if err != nil {
		t.Fatalf("issued_at must be a valid RFC3339 timestamp, got %q: %v", response.IssuedAt, err)
	}

	if delta := time.Since(issuedAt); delta < 0 || delta > time.Minute {
		t.Fatalf("issued_at should reflect the current time, got %s (delta %s)", issuedAt, delta)
	}
}


func TestRequireAuthRejectsAnonymousRepositoryRequests(t *testing.T) {
	server, teardown := setupTestServerWithAuth(t, true)
	defer teardown()

	req := httptest.NewRequest(http.MethodGet, "/v2/library/alpine/tags/list", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected anonymous request to be rejected with 401, got %d", rec.Code)
	}
	if rec.Header().Get("Www-Authenticate") == "" {
		t.Fatal("expected an OCI Bearer authentication challenge")
	}
}

func TestRequireAuthEnforcesRepositoryActionScopes(t *testing.T) {
	server, teardown := setupTestServerWithAuth(t, true)
	defer teardown()

	token, err := server.Authenticator().IssueToken("reader", []proxy.ResourceAccess{
		{Type: "repository", Name: "library/alpine", Actions: []string{"pull"}},
	})
	if err != nil {
		t.Fatalf("failed to issue scoped token: %v", err)
	}

	readReq := httptest.NewRequest(http.MethodGet, "/v2/library/alpine/tags/list", nil)
	readReq.Header.Set("Authorization", "Bearer "+token)
	readRec := httptest.NewRecorder()
	server.ServeHTTP(readRec, readReq)
	if readRec.Code != http.StatusOK {
		t.Fatalf("expected scoped pull request to succeed, got %d: %s", readRec.Code, readRec.Body.String())
	}

	writeReq := httptest.NewRequest(http.MethodPost, "/v2/library/alpine/blobs/uploads/", nil)
	writeReq.Header.Set("Authorization", "Bearer "+token)
	writeRec := httptest.NewRecorder()
	server.ServeHTTP(writeRec, writeReq)
	if writeRec.Code != http.StatusForbidden {
		t.Fatalf("expected pull-only token to be denied push access with 403, got %d", writeRec.Code)
	}
}

func TestRequireAuthAllowsPublicVersionCheck(t *testing.T) {
	server, teardown := setupTestServerWithAuth(t, true)
	defer teardown()

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected OCI version check to remain public, got %d", rec.Code)
	}
}
