package ppforward

import (
	"encoding/json"
	"fmt"
	"os"
)

type Rule struct {
	Listen string `json:"listen"`
	Target string `json:"target"`
	Tag    string `json:"tag,omitempty"`
}

type Config struct {
	Rules []Rule `json:"rules"`
}

func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	for idx, rule := range cfg.Rules {
		if rule.Listen == "" || rule.Target == "" {
			return Config{}, fmt.Errorf("rule %d: listen and target are required", idx)
		}
	}

	return cfg, nil
}
