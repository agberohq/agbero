package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll/lx"
)

type Victoria struct {
	url    string
	client *http.Client
	mu     sync.Mutex
	dev    bool
}

func NewVictoriaHandler(url string, dev bool) *Victoria {
	return &Victoria{
		url: url,
		dev: dev,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (h *Victoria) Handle(e *lx.Entry) error {
	env := "production"
	if h.dev {
		env = "development"
	}

	hostname, _ := os.Hostname()

	line := map[string]interface{}{
		"ts":    e.Timestamp.Format(time.RFC3339Nano),
		"level": strings.ToLower(e.Level.String()),
		"msg":   e.Message,
		"ns":    e.Namespace,
		"app":   woos.Name,
		"ver":   woos.Version,
		"env":   env,
		"host":  hostname,
	}

	for k, v := range e.Fields {
		line[k] = v
	}

	if len(e.Stack) > 0 {
		line["stack"] = string(e.Stack)
	}

	b, err := json.Marshal(line)
	if err != nil {
		return err
	}

	data := append(b, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()

	victoriaURL := fmt.Sprintf("%s/insert/jsonline?"+
		"_msg_field=msg"+
		"&_time_field=ts"+
		"&_stream_fields=app,env,level,ns,host", h.url)

	resp, err := h.client.Post(victoriaURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("VictoriaLogs rejected: %d", resp.StatusCode)
	}

	return nil
}
