package proto

type ExecRequest struct {
	ID             int64  `json:"id"`
	Cmd            string `json:"cmd"`
	TimeoutMs      int    `json:"timeout_ms"`
	MaxOutputChars int    `json:"max_output_chars"`
}

type ExecResponse struct {
	ID         int64  `json:"id"`
	ExitCode   int    `json:"exit_code"`
	Cwd        string `json:"cwd"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Truncated  bool   `json:"truncated"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}
