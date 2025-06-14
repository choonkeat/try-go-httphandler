package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"
)

var (
	host = flag.String("host", "localhost", "Server host")
	port = flag.Int("port", 8080, "Server port")
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	if err := errmain(ctx); err != nil {
		cancel()
		log.Fatalln(err)
	}
}

func errmain(ctx context.Context) error {
	flag.Parse()

	config := Config{
		Host: *host,
		Port: *port,
	}

	// Run HTTP server
	return runCtxFuncs(ctx, func(ctx context.Context) error {
		return httpServerFunc(ctx, config)
	})
}

func runCtxFuncs(parentCtx context.Context, services ...func(context.Context) error) error {
	g, ctx := errgroup.WithContext(parentCtx)

	for _, service := range services {
		service := service // capture loop variable
		g.Go(func() error {
			return service(ctx)
		})
	}

	return g.Wait()
}