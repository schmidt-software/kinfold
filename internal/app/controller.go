package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"my-zerotier/internal/relay"
)

func serveController(ctx context.Context, server *http.Server, listener net.Listener, handler *relay.Server, watch func(context.Context), grace time.Duration) error {
	defer listener.Close()
	watchCtx, stopWatch := context.WithCancel(context.Background())
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		watch(watchCtx)
	}()
	defer func() {
		stopWatch()
		<-watchDone
	}()
	served := make(chan error, 1)
	go func() { served <- server.ServeTLS(listener, "", "") }()
	var serveErr error
	select {
	case serveErr = <-served:
		handler.Close()
		if !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	case <-ctx.Done():
	}
	stopWatch()
	handler.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
	shutdownErr := server.Shutdown(shutdownCtx)
	cancel()
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, server.Close())
	}
	serveErr = <-served
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	if shutdownErr != nil {
		shutdownErr = fmt.Errorf("controller shutdown: %w", shutdownErr)
	}
	return errors.Join(serveErr, shutdownErr)
}
