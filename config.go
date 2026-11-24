package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/mcuadros/go-defaults"
	"gopkg.in/yaml.v3"
)

var DEFAULT_BYPASS_LIST = []string{
	"127.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"224.0.0.0/4",
	"fe80::/10",
	"+.lan",
	"+.local",
	"+.internal",
}

const DomainSep = "."

const DOMAIN_RULE_SPECIAL_CHARS = "*+."

// DomainRuleNode stores one node in a reversed-label domain rule index.
type DomainRuleNode struct {
	Children           map[string]*DomainRuleNode
	Exact              bool
	Suffix             bool
	MinUnmatchedLabels int
}

// DomainRuleIndex is a reversed-label trie keyed from the top-level domain.
type DomainRuleIndex map[string]*DomainRuleNode

func (index DomainRuleIndex) insert(rule string) error {
	if rule == "" {
		return fmt.Errorf("domain rule cannot be empty")
	}
	minUnmatchedLabels := -1
	if strings.HasPrefix(rule, "+.") {
		minUnmatchedLabels = 0
		rule = strings.TrimPrefix(rule, "+.")
	} else if strings.HasPrefix(rule, ".") {
		minUnmatchedLabels = 1
		rule = strings.TrimPrefix(rule, ".")
	}
	if rule == "" || strings.HasPrefix(rule, ".") || strings.HasSuffix(rule, ".") {
		return fmt.Errorf("malformed domain rule")
	}
	labels := strings.Split(strings.ToLower(rule), DomainSep)
	if slices.ContainsFunc(labels, func(label string) bool {
		return label == "" || strings.ContainsAny(label, "+") || (strings.Contains(label, "*") && label != "*")
	}) {
		return fmt.Errorf("wildcard operators must occupy a complete label and `+` must prefix the domain")
	}
	if minUnmatchedLabels >= 0 && slices.Contains(labels, "*") {
		return fmt.Errorf("`*` cannot be combined with a suffix operator")
	}

	nodeMap := map[string]*DomainRuleNode(index)
	var terminal *DomainRuleNode
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		node := nodeMap[label]
		if node == nil {
			node = &DomainRuleNode{Children: make(map[string]*DomainRuleNode)}
			nodeMap[label] = node
		}
		terminal = node
		nodeMap = node.Children
	}
	if minUnmatchedLabels < 0 {
		terminal.Exact = true
	} else if !terminal.Suffix || minUnmatchedLabels < terminal.MinUnmatchedLabels {
		terminal.Suffix = true
		terminal.MinUnmatchedLabels = minUnmatchedLabels
	}
	return nil
}

func (index DomainRuleIndex) IsEmpty() bool {
	return len(index) == 0
}

// Matches looks up a domain by traversing labels from right to left.
func (index DomainRuleIndex) Matches(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), DomainSep)
	if domain == "" {
		return false
	}

	labels := strings.Split(domain, DomainSep)
	if slices.Contains(labels, "") {
		return false
	}

	var visit func(map[string]*DomainRuleNode, int) bool
	visit = func(nodes map[string]*DomainRuleNode, depth int) bool {
		if depth == len(labels) {
			return false
		}
		label := labels[len(labels)-depth-1]
		for _, key := range []string{label, "*"} {
			child := nodes[key]
			if child == nil {
				continue
			}
			unmatched := len(labels) - depth - 1
			if child.Exact && unmatched == 0 || child.Suffix && unmatched >= child.MinUnmatchedLabels {
				return true
			}
			if visit(child.Children, depth+1) {
				return true
			}
		}
		return false
	}
	return visit(map[string]*DomainRuleNode(index), 0)
}

type Config struct {
	LogLevel      string          `yaml:"log-level" default:"warn"` // `false` or `silent` to disable
	LogSource     bool            `yaml:"log-source" default:"false"`
	LogJSON       bool            `yaml:"log-json" default:"true"`
	HTTPPort      uint16          `yaml:"http-port" default:"59080"`  // HTTP Port, `0` to disable
	ProxyPort     uint16          `yaml:"proxy-port" default:"59123"` // HTTP Proxy Port, `0` to disable
	RedirectList  *[]string       `yaml:"redirect-list"`
	BypassList    *[]string       `yaml:"bypass-list"`
	RedirectRules DomainRuleIndex `yaml:"-"`
	BypassRules   DomainRuleIndex `yaml:"-"`
	RedirectCIDRs []netip.Prefix  `yaml:"-"`
	BypassCIDRs   []netip.Prefix  `yaml:"-"`
}

func (c *Config) MatchRedirectAddr(addr netip.Addr) bool {
	return len(c.RedirectCIDRs) == 0 || matchesCIDR(c.RedirectCIDRs, addr)
}

func (c *Config) MatchBypassAddr(addr netip.Addr) bool {
	return matchesCIDR(c.BypassCIDRs, addr)
}

func (c *Config) MatchRedirectDomain(domain string) bool {
	return c.RedirectRules.IsEmpty() || c.RedirectRules.Matches(strings.ToLower(domain))
}

func (c *Config) MatchBypassDomain(domain string) bool {
	return c.BypassRules.Matches(strings.ToLower(domain))
}

func matchesCIDR(prefixes []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (c *Config) ParseRules() error {
	if c.RedirectList == nil {
		var emptyList []string = nil
		c.RedirectList = &emptyList
	}
	if c.BypassList == nil {
		defaultList := slices.Clone(DEFAULT_BYPASS_LIST)
		c.BypassList = &defaultList
	}

	parse := func(raw []string) (DomainRuleIndex, []netip.Prefix, error) {
		index := make(DomainRuleIndex)
		var cidrs []netip.Prefix
		for idx, value := range raw {
			if cidr, err := netip.ParsePrefix(value); err == nil {
				cidrs = append(cidrs, cidr)
				continue
			}
			if err := index.insert(value); err != nil {
				return nil, nil, fmt.Errorf("rule %d (%q): %w", idx, value, err)
			}
		}
		return index, cidrs, nil
	}

	redirectRules, redirectCIDRs, err := parse(*c.RedirectList)
	if err != nil {
		return fmt.Errorf("redirect list: %w", err)
	}
	bypassRules, bypassCIDRs, err := parse(*c.BypassList)
	if err != nil {
		return fmt.Errorf("bypass list: %w", err)
	}
	c.RedirectRules = redirectRules
	c.BypassRules = bypassRules
	c.RedirectCIDRs = redirectCIDRs
	c.BypassCIDRs = bypassCIDRs

	return nil
}

func (c *Config) Parse() error {
	return c.ParseRules()
}

type ConfigLoader struct {
	filename     string
	config       atomic.Pointer[Config]
	yamlDocument *yaml.Node
}

func (cl *ConfigLoader) Config() *Config {
	c := cl.config.Load()
	if c == nil {
		panic("config not loaded")
	}

	return c
}

func (cl *ConfigLoader) Load() error {
	data, err := os.ReadFile(cl.filename)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read config %q: %w", cl.filename, err)
	}

	config := &Config{}
	defaults.SetDefaults(config)
	if err == nil {
		document := &yaml.Node{}
		if err := yaml.Unmarshal(data, document); err != nil {
			return fmt.Errorf("parse config %q: %w", cl.filename, err)
		}
		if err := document.Decode(config); err != nil {
			return fmt.Errorf("decode config %q: %w", cl.filename, err)
		}
		cl.yamlDocument = document
	}
	if err := config.Parse(); err != nil {
		return err
	}
	cl.config.Store(config)

	if os.IsNotExist(err) {
		return cl.Save()
	}
	return nil
}

func (cl *ConfigLoader) Save() error {
	config := cl.config.Load()
	if config == nil {
		config = &Config{}
		defaults.SetDefaults(config)
	}
	if err := config.Parse(); err != nil {
		return err
	}

	document, err := configYAMLDocument(config, cl.yamlDocument)
	if err != nil {
		return fmt.Errorf("serialize config %q: %w", cl.filename, err)
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("serialize config %q: %w", cl.filename, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("serialize config %q: %w", cl.filename, err)
	}
	data := buffer.Bytes()
	if err := os.WriteFile(cl.filename, data, 0o600); err != nil {
		return fmt.Errorf("write config %q: %w", cl.filename, err)
	}
	cl.config.Store(config)
	cl.yamlDocument = document
	return nil
}

func configYAMLDocument(config *Config, previous *yaml.Node) (*yaml.Node, error) {
	encoded, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	document := &yaml.Node{}
	if err := yaml.Unmarshal(encoded, document); err != nil {
		return nil, err
	}
	if previous != nil {
		copyYAMLComments(document, previous)
	}
	return document, nil
}

func copyYAMLComments(dst, src *yaml.Node) {
	dst.HeadComment = src.HeadComment
	dst.LineComment = src.LineComment
	dst.FootComment = src.FootComment
	switch dst.Kind {
	case yaml.DocumentNode:
		if src.Kind == yaml.DocumentNode && len(dst.Content) > 0 && len(src.Content) > 0 {
			copyYAMLComments(dst.Content[0], src.Content[0])
		}
	case yaml.MappingNode:
		if src.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(dst.Content); i += 2 {
			key, value := dst.Content[i], dst.Content[i+1]
			for j := 0; j+1 < len(src.Content); j += 2 {
				if src.Content[j].Value == key.Value {
					copyYAMLComments(key, src.Content[j])
					copyYAMLComments(value, src.Content[j+1])
					break
				}
			}
		}
	case yaml.SequenceNode:
		if src.Kind != yaml.SequenceNode {
			return
		}
		for i := 0; i < len(dst.Content) && i < len(src.Content); i++ {
			copyYAMLComments(dst.Content[i], src.Content[i])
		}
	}
}
