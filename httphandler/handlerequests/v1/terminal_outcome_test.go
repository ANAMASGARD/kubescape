package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/require"
)

type scanStatusResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Outcome string `json:"outcome"`
	Error   string `json:"error"`
}

type panicOnceResponseWriter struct {
	*httptest.ResponseRecorder
	panicked bool
}

func (w *panicOnceResponseWriter) WriteHeader(code int) {
	if !w.panicked {
		w.panicked = true
		panic("response writer failed")
	}
	w.ResponseRecorder.WriteHeader(code)
}

func getScanStatus(t *testing.T, h *HTTPHandler, id string) scanStatusResponse {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/v1/status?id="+url.QueryEscape(id), nil)
	recorder := httptest.NewRecorder()
	h.Status(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	var response scanStatusResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	return response
}

func TestAsyncScanStatusReportsSuccessAfterLeavingBusy(t *testing.T) {
	original := scanImpl
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		close(started)
		<-release
		return nil, nil
	}
	h := NewHTTPHandler(false)
	defer func() {
		releaseOnce.Do(func() { close(release) })
		require.NoError(t, h.Shutdown(context.Background(), 0))
		scanImpl = original
	}()

	accepted := performAsyncScanRequest(t, h, `{}`)
	require.Equal(t, http.StatusOK, accepted.Code)
	id := decodeScanResponse(t, accepted).ID
	require.NotEmpty(t, id)
	<-started

	busy := getScanStatus(t, h, id)
	require.Equal(t, string(utilsapisv1.BusyScanResponseType), busy.Type)
	require.Equal(t, id, busy.ID)
	require.Empty(t, busy.Outcome)

	releaseOnce.Do(func() { close(release) })
	var completed scanStatusResponse
	require.Eventually(t, func() bool {
		completed = getScanStatus(t, h, id)
		return completed.Type == string(utilsapisv1.NotBusyScanResponseType)
	}, time.Second, time.Millisecond)
	require.Equal(t, id, completed.ID)
	require.Equal(t, "succeeded", completed.Outcome)
	require.Empty(t, completed.Error)
}

func TestScanRequestPanicDoesNotClearActiveScanStatus(t *testing.T) {
	original := scanImpl
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		close(started)
		<-release
		return nil, nil
	}
	h := NewHTTPHandler(false)
	defer func() {
		releaseOnce.Do(func() { close(release) })
		require.NoError(t, h.Shutdown(context.Background(), 0))
		scanImpl = original
	}()

	w := &panicOnceResponseWriter{ResponseRecorder: httptest.NewRecorder()}
	h.Scan(w, httptest.NewRequest(http.MethodPost, "/v1/scan", strings.NewReader(`{}`)))
	<-started
	// The writer failed before the ordinary accepted response was sent, so the
	// request cannot supply the scan ID. The id-less status path tracks the
	// latest accepted user scan and must still report it as running.
	status := getScanStatus(t, h, "")
	require.Equal(t, string(utilsapisv1.BusyScanResponseType), status.Type)
	require.Empty(t, status.Outcome)
	require.NotEmpty(t, status.ID)

	releaseOnce.Do(func() { close(release) })
	h.BeginShutdown()
	<-h.workerDone
	require.Equal(t, "succeeded", getScanStatus(t, h, status.ID).Outcome)
}

func TestAsyncScanStatusReportsFailureWithoutExposingScannerError(t *testing.T) {
	original := scanImpl
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		return nil, errors.New("sensitive scanner detail")
	}
	defer func() { scanImpl = original }()

	h := NewHTTPHandler(false)
	accepted := performAsyncScanRequest(t, h, `{}`)
	require.Equal(t, http.StatusOK, accepted.Code)
	id := decodeScanResponse(t, accepted).ID
	h.BeginShutdown()
	<-h.workerDone

	status := getScanStatus(t, h, id)
	require.Equal(t, string(utilsapisv1.NotBusyScanResponseType), status.Type)
	require.Equal(t, id, status.ID)
	require.Equal(t, "failed", status.Outcome)
	require.Equal(t, "scan failed", status.Error)
}

func TestAsyncScanStatusReportsEngineFailureThroughProductionScan(t *testing.T) {
	withTempOutputDirs(t)
	originalScan, originalEngine := scanImpl, runKubescapeScan
	scanImpl = scan
	runKubescapeScan = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
		return nil, errors.New("failed to load /tmp/private-scan-input")
	}
	h := NewHTTPHandler(false)
	defer func() {
		_ = h.Shutdown(context.Background(), 0)
		scanImpl, runKubescapeScan = originalScan, originalEngine
	}()

	accepted := performAsyncScanRequest(t, h, `{}`)
	require.Equal(t, http.StatusOK, accepted.Code)
	id := decodeScanResponse(t, accepted).ID
	h.BeginShutdown()
	<-h.workerDone

	status := getScanStatus(t, h, id)
	require.Equal(t, string(utilsapisv1.NotBusyScanResponseType), status.Type)
	require.Equal(t, id, status.ID)
	require.Equal(t, "failed", status.Outcome)
	require.Equal(t, "scan failed", status.Error)
}

func TestAsyncScanStatusReportsCancellation(t *testing.T) {
	withTempOutputDirs(t)
	original := scanImpl
	started := make(chan struct{})
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	h := NewHTTPHandler(false)
	defer func() {
		require.NoError(t, h.Shutdown(context.Background(), 0))
		scanImpl = original
	}()

	accepted := performAsyncScanRequest(t, h, `{}`)
	require.Equal(t, http.StatusOK, accepted.Code)
	id := decodeScanResponse(t, accepted).ID
	<-started
	cancelled := httptest.NewRecorder()
	h.CancelScan(cancelled, httptest.NewRequest(http.MethodDelete, "/v1/scan?id="+url.QueryEscape(id), nil))
	require.Equal(t, http.StatusOK, cancelled.Code)
	h.BeginShutdown()
	<-h.workerDone

	status := getScanStatus(t, h, id)
	require.Equal(t, string(utilsapisv1.NotBusyScanResponseType), status.Type)
	require.Equal(t, id, status.ID)
	require.Equal(t, "cancelled", status.Outcome)
	require.Equal(t, "scan cancelled", status.Error)
}

func TestQueuedScanStatusReportsCancellationWithoutRunning(t *testing.T) {
	original := scanImpl
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	calls := 0
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		calls++
		if calls == 1 {
			close(started)
			<-release
		}
		return nil, nil
	}
	h := NewHTTPHandler(false)
	defer func() {
		releaseOnce.Do(func() { close(release) })
		require.NoError(t, h.Shutdown(context.Background(), 0))
		scanImpl = original
	}()

	first := decodeScanResponse(t, performAsyncScanRequest(t, h, `{}`)).ID
	<-started
	second := decodeScanResponse(t, performAsyncScanRequest(t, h, `{}`)).ID
	queued := getScanStatus(t, h, second)
	require.Equal(t, string(utilsapisv1.BusyScanResponseType), queued.Type)
	require.Empty(t, queued.Outcome)

	cancelled := httptest.NewRecorder()
	h.CancelScan(cancelled, httptest.NewRequest(http.MethodDelete, "/v1/scan?id="+url.QueryEscape(second), nil))
	require.Equal(t, http.StatusOK, cancelled.Code)
	releaseOnce.Do(func() { close(release) })
	h.BeginShutdown()
	<-h.workerDone

	require.Equal(t, 1, calls, "a cancelled queued scan must never reach the scanner")
	require.Equal(t, "succeeded", getScanStatus(t, h, first).Outcome)
	status := getScanStatus(t, h, second)
	require.Equal(t, string(utilsapisv1.NotBusyScanResponseType), status.Type)
	require.Equal(t, second, status.ID)
	require.Equal(t, "cancelled", status.Outcome)
	require.Equal(t, "scan cancelled", status.Error)
}

func TestAsyncScanStatusReportsPanicAsFailure(t *testing.T) {
	withTempOutputDirs(t)
	original := scanImpl
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		panic("sensitive scanner detail")
	}
	defer func() { scanImpl = original }()

	h := NewHTTPHandler(false)
	id := decodeScanResponse(t, performAsyncScanRequest(t, h, `{}`)).ID
	h.BeginShutdown()
	<-h.workerDone

	status := getScanStatus(t, h, id)
	require.Equal(t, string(utilsapisv1.NotBusyScanResponseType), status.Type)
	require.Equal(t, id, status.ID)
	require.Equal(t, "failed", status.Outcome)
	require.Equal(t, "scan panicked", status.Error)
}

func TestScanStatusDoesNotInferSuccessForUnknownOrRestartedScan(t *testing.T) {
	original := scanImpl
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		return nil, nil
	}
	defer func() { scanImpl = original }()

	h := NewHTTPHandler(false)
	unknownID := "123e4567-e89b-12d3-a456-426614174000"
	before := getScanStatus(t, h, unknownID)
	require.Equal(t, string(utilsapisv1.NotBusyScanResponseType), before.Type)
	require.Equal(t, unknownID, before.ID)
	require.Equal(t, "unknown", before.Outcome)
	require.Empty(t, before.Error)

	id := decodeScanResponse(t, performAsyncScanRequest(t, h, `{}`)).ID
	h.BeginShutdown()
	<-h.workerDone
	require.Equal(t, "succeeded", getScanStatus(t, h, id).Outcome)

	restarted := NewHTTPHandler(false)
	restarted.BeginShutdown()
	<-restarted.workerDone
	status := getScanStatus(t, restarted, id)
	require.Equal(t, string(utilsapisv1.NotBusyScanResponseType), status.Type)
	require.Equal(t, id, status.ID)
	require.Equal(t, "unknown", status.Outcome)
	require.Empty(t, status.Error)
}

func TestScanStatusRetainsOnlyTheMostRecentUserOutcomes(t *testing.T) {
	original := scanImpl
	scanImpl = func(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier, string, bool) (*reporthandlingv2.PostureReport, error) {
		return nil, nil
	}
	defer func() { scanImpl = original }()

	h := newHTTPHandler(false, terminalOutcomeLimit+1, defaultMaxScanRequestBodyBytes)
	ids := make([]string, 0, terminalOutcomeLimit+1)
	for range terminalOutcomeLimit + 1 {
		accepted := performAsyncScanRequest(t, h, `{}`)
		require.Equal(t, http.StatusOK, accepted.Code)
		ids = append(ids, decodeScanResponse(t, accepted).ID)
	}
	h.BeginShutdown()
	<-h.workerDone

	require.Equal(t, "unknown", getScanStatus(t, h, ids[0]).Outcome, "the oldest outcome must be evicted")
	require.Equal(t, "succeeded", getScanStatus(t, h, ids[1]).Outcome)
	last := getScanStatus(t, h, ids[len(ids)-1])
	require.Equal(t, "succeeded", last.Outcome)
	require.Equal(t, ids[len(ids)-1], getScanStatus(t, h, "").ID, "the implicit latest scan must still resolve")
}
