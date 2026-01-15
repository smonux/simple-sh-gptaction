package main

import (
	"encoding/json"
	"io"
	"log"
	"os"

	"gptsh/internal/config"
	"gptsh/internal/proto"
	"gptsh/internal/sandbox"
	"gptsh/internal/shell"
)

func main() {
	cfg, err := config.LoadExecutorConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := sandbox.Apply(sandbox.Config{
		WriteAllow:       cfg.WriteAllow,
		BindTCPAllow:     cfg.BindTCPAllow,
		AllowOutgoingTCP: cfg.AllowOutgoingTCP,
		AllowIOCTLDev:    cfg.AllowIOCTLDev,
	}); err != nil {
		log.Fatalf("sandbox: %v", err)
	}

	bash, err := shell.Start(cfg.BashPath)
	if err != nil {
		log.Fatalf("bash: %v", err)
	}
	defer bash.Close()

	for {
		frame, err := proto.ReadFrame(os.Stdin)
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Fatalf("read frame: %v", err)
		}
		var req proto.ExecRequest
		if err := json.Unmarshal(frame, &req); err != nil {
			log.Fatalf("decode request: %v", err)
		}
		stdout, stderr, exitCode, cwd, truncated, durationMs, err := bash.Exec(req.Cmd, req.MaxOutputChars)
		resp := proto.ExecResponse{
			ID:         req.ID,
			ExitCode:   exitCode,
			Cwd:        cwd,
			Stdout:     stdout,
			Stderr:     stderr,
			Truncated:  truncated,
			DurationMs: durationMs,
		}
		if err != nil {
			resp.Error = err.Error()
			log.Printf("exec error: id=%d err=%v", req.ID, err)
		}
		payload, err := json.Marshal(resp)
		if err != nil {
			log.Fatalf("encode response: %v", err)
		}
		if err := proto.WriteFrame(os.Stdout, payload); err != nil {
			log.Fatalf("write frame: %v", err)
		}
	}
}
