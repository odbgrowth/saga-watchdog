package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/odbgrowth/saga-watchdog/internal/dockerwatch"
)

func dockerCLI(args []string) int {
	if len(args) == 0 {
		return fail(errors.New("usage: saga-watchdog docker validate|watch|status|events --config FILE"))
	}
	op := args[0]
	switch op {
	case "validate", "watch", "status", "events":
	default:
		return fail(errors.New("unknown Docker command; use validate, watch, status or events"))
	}
	f := flag.NewFlagSet("docker "+op, flag.ContinueOnError)
	path := f.String("config", "", "path to the Docker observer YAML")
	once := false
	if op == "watch" {
		f.BoolVar(&once, "once", false, "record one inspection and exit without starting an event stream")
	}
	if err := f.Parse(args[1:]); err != nil {
		return 2
	}
	if *path == "" || f.NArg() != 0 {
		return fail(errors.New("--config FILE is required; positional arguments are not accepted"))
	}
	c, err := dockerwatch.Load(*path)
	if err != nil {
		return fail(err)
	}
	switch op {
	case "validate":
		fmt.Println("Docker observer configuration valid (observe only; no container changes)")
		return 0
	case "status":
		s, err := dockerwatch.ReadSnapshot(c)
		if err != nil {
			return fail(err)
		}
		s.Refresh(c, time.Now().UTC())
		if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
			return fail(err)
		}
		return 0
	case "events":
		if _, err := dockerwatch.ReadSnapshot(c); err != nil {
			return fail(err)
		}
		if err := dockerwatch.CopyHistory(c.StateDir, os.Stdout); err != nil {
			return fail(err)
		}
		return 0
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return fail(errors.New("Docker observation requires Linux or macOS with a local Unix socket"))
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	client := dockerwatch.NewClient(c.Socket, c.RequestTimeout)
	defer client.Close()
	fmt.Fprintln(os.Stderr, "SAGA Docker observer: observe only; stopping SAGA leaves selected containers running")
	if err := dockerwatch.Run(ctx, c, client, once); err != nil {
		return fail(err)
	}
	if once {
		s, err := dockerwatch.ReadSnapshot(c)
		if err != nil {
			return fail(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
			return fail(err)
		}
		for _, t := range s.Targets {
			if t.Availability != "present" || t.StatsError != "" {
				return 2
			}
		}
	}
	return 0
}
