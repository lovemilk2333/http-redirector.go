package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigLoaderCreatesDefaultConfig(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.yaml")
	loader := &ConfigLoader{filename: filename}

	if err := loader.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loader.Config().Rules == nil || len(*loader.Config().Rules) != len(DEFAULT_BYPASS_LIST) {
		t.Fatalf("Rules = %#v, want converted default bypass rules", loader.Config().Rules)
	}
	for i, defaultRule := range DEFAULT_BYPASS_LIST {
		if got, want := (*loader.Config().Rules)[i], defaultRule+";bypass"; got != want {
			t.Errorf("default rule %d = %q, want %q", i, got, want)
		}
	}
	if _, err := os.Stat(filename); err != nil {
		t.Fatalf("default config was not saved: %v", err)
	}
}

func TestConfigLoaderPreservesExplicitEmptyRules(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(filename, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loader := &ConfigLoader{filename: filename}

	if err := loader.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loader.Config().Rules == nil || *loader.Config().Rules == nil || len(*loader.Config().Rules) != 0 {
		t.Fatalf("Rules = %#v, want explicit empty list", loader.Config().Rules)
	}
	if err := loader.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	reloaded := &ConfigLoader{filename: filename}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload error = %v", err)
	}
	if reloaded.Config().Rules == nil || *reloaded.Config().Rules == nil || len(*reloaded.Config().Rules) != 0 {
		t.Fatalf("reloaded Rules = %#v, want explicit empty list", reloaded.Config().Rules)
	}
}

func TestConfigLoaderPreservesDisabledPorts(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(filename, []byte("http-port: 0\nproxy-port: 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loader := &ConfigLoader{filename: filename}

	if err := loader.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loader.Config().HTTPPort != 0 || loader.Config().ProxyPort != 0 {
		t.Fatalf("ports after load = HTTP %d, proxy %d, want both disabled", loader.Config().HTTPPort, loader.Config().ProxyPort)
	}
	if err := loader.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	reloaded := &ConfigLoader{filename: filename}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload error = %v", err)
	}
	if reloaded.Config().HTTPPort != 0 || reloaded.Config().ProxyPort != 0 {
		t.Fatalf("ports after reload = HTTP %d, proxy %d, want both disabled", reloaded.Config().HTTPPort, reloaded.Config().ProxyPort)
	}
}

func TestConfigLoaderUsesTwoSpaceIndentAndPreservesComments(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.yaml")
	input := "# project settings\nhttp-port: 0 # disable HTTP\nrules:\n  - 10.0.0.0/8;bypass # private network\n"
	if err := os.WriteFile(filename, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	loader := &ConfigLoader{filename: filename}
	if err := loader.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := loader.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# project settings",
		"http-port: 0 # disable HTTP",
		"  - 10.0.0.0/8;bypass # private network",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("saved config does not contain %q:\n%s", want, data)
		}
	}
}

func TestConfigBuildsReversedDomainRuleIndexes(t *testing.T) {
	rules := []string{"xbox.*.microsoft.com;redirect", "+.baidu.com;redirect", ".lan;redirect", "192.168.0.0/16;bypass", "WWW.Example.COM;bypass"}
	config := &Config{
		Rules: &rules,
	}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	for _, domain := range []string{"xbox.a.microsoft.com", "xbox.b.microsoft.com", "baidu.com", "tieba.baidu.com", "123.tieba.baidu.com", "foo.lan", "a.b.lan"} {
		if config.ResolveDomain(domain) != RuleRedirect {
			t.Errorf("RedirectRules.Matches(%q) = false, want true", domain)
		}
	}
	for _, domain := range []string{"xbox.microsoft.com", "a.xbox.b.microsoft.com", "lan"} {
		if config.ResolveDomain(domain) == RuleRedirect {
			t.Errorf("RedirectRules.Matches(%q) = true, want false", domain)
		}
	}
	if config.ResolveDomain("www.example.com") != RuleBypass || config.ResolveDomain("WWW.EXAMPLE.COM.") != RuleBypass {
		t.Fatal("domain index should normalize labels to lowercase and ignore a trailing dot")
	}
	if len(config.CompiledRules) != 5 || !config.CompiledRules[3].IsCIDR || config.CompiledRules[3].Prefix.String() != "192.168.0.0/16" {
		t.Fatalf("compiled rules do not preserve input order and CIDR identity: %#v", config.CompiledRules)
	}
	if _, ok := config.CompiledRules[0].Index["com"].Children["microsoft"].Children["*"]; !ok {
		t.Fatal("domain rules are not stored as a reversed-label index")
	}
}

func TestConfigMatchMethods(t *testing.T) {
	rules := []string{"+.example.com;redirect", "10.0.0.0/8;redirect", "+.blocked.example;deny", "203.0.113.0/24;deny", ".internal;bypass", "192.168.0.0/16;bypass"}
	config := &Config{Rules: &rules}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	if !config.MatchRedirectDomain("API.Example.Com") || config.MatchRedirectDomain("other.net") {
		t.Fatal("MatchRedirectDomain returned an unexpected result")
	}
	if !config.MatchBypassDomain("printer.internal") || config.MatchBypassDomain("internal") {
		t.Fatal("MatchBypassDomain returned an unexpected result")
	}
	if !config.MatchDenyDomain("www.blocked.example") || !config.MatchDenyDomain("example") {
		t.Fatal("MatchDenyDomain returned an unexpected result")
	}
	if !config.MatchRedirectAddr(netip.MustParseAddr("10.2.3.4")) || config.MatchRedirectAddr(netip.MustParseAddr("192.168.1.2")) {
		t.Fatal("MatchRedirectAddr returned an unexpected result")
	}
	if !config.MatchBypassAddr(netip.MustParseAddr("192.168.1.2")) || config.MatchBypassAddr(netip.MustParseAddr("10.2.3.4")) {
		t.Fatal("MatchBypassAddr returned an unexpected result")
	}
	if !config.MatchDenyAddr(netip.MustParseAddr("203.0.113.9")) || !config.MatchDenyAddr(netip.MustParseAddr("203.0.114.9")) {
		t.Fatal("MatchDenyAddr returned an unexpected result, unmatched addresses should be denied")
	}
}

func TestDefaultRulesBypassListAndDoNotRedirect(t *testing.T) {
	config := &Config{}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	if config.MatchRedirectDomain("example.com") || config.MatchBypassDomain("example.com") {
		t.Error("unlisted domain should not match redirect or bypass rules")
	}
	if !config.MatchBypassDomain("printer.lan") || config.MatchRedirectDomain("printer.lan") {
		t.Error("default bypass rules were not compiled as bypass-only rules")
	}
	for _, domain := range []string{"bad_name.example", strings.Repeat("a", MaxDomainLabelLength+1) + ".com", strings.Repeat("a.", 126) + "aa"} {
		if config.MatchRedirectDomain(domain) {
			t.Errorf("MatchRedirectDomain(%q) = true, want false for invalid domain", domain)
		}
	}
}

func TestRedirectRulesDoNotMatchOtherHostKindsByDefault(t *testing.T) {
	rules := []string{"+.example.com;redirect"}
	config := &Config{Rules: &rules}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}
	if config.MatchRedirectAddr(netip.MustParseAddr("203.0.113.1")) {
		t.Error("domain-only redirect list matched an IP address")
	}

	rules = []string{"203.0.113.0/24;redirect"}
	config = &Config{Rules: &rules}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}
	if config.MatchRedirectDomain("example.com") {
		t.Error("CIDR-only redirect list matched a domain")
	}
}

func TestDomainRuleIndexEnforcesDomainLimitsAndSyntax(t *testing.T) {
	index := make(DomainRuleIndex)
	if err := index.insert("+.example.com"); err != nil {
		t.Fatalf("insert valid rule: %v", err)
	}

	maxLengthDomain := strings.Repeat("a.", 126) + "a"
	if len(maxLengthDomain) != MaxDomainLength {
		t.Fatalf("test domain length = %d, want %d", len(maxLengthDomain), MaxDomainLength)
	}
	if err := index.insert(maxLengthDomain); err != nil {
		t.Errorf("insert valid maximum-length domain: %v", err)
	}
	if !index.Matches(maxLengthDomain) {
		t.Error("maximum-length domain with 127 labels did not match")
	}

	invalidDomains := []string{
		strings.Repeat("a.", 126) + "aa",
		strings.Repeat("a", MaxDomainLabelLength+1) + ".com",
		"bad..example.com",
		"-bad.example.com",
		"bad-.example.com",
		"bad_name.example.com",
		"bad!.example.com",
		"éxample.com",
		"example.com..",
	}
	for _, domain := range invalidDomains {
		t.Run(domain, func(t *testing.T) {
			if err := index.insert(domain); err == nil {
				t.Errorf("insert(%q) succeeded, want invalid-domain error", domain)
			}
			if index.Matches(domain) {
				t.Errorf("Matches(%q) = true, want false for invalid domain", domain)
			}
		})
	}

	if err := index.insert("xbox.*.microsoft.com"); err != nil {
		t.Errorf("insert valid wildcard-label rule: %v", err)
	}
}

func TestDomainRulePlusMatchesAnyDomain(t *testing.T) {
	anyDomain := make(DomainRuleIndex)
	if err := anyDomain.insert("+"); err != nil {
		t.Fatalf("insert catch-all rule: %v", err)
	}
	for _, domain := range []string{"example.com", "a.b.example.com", "localhost"} {
		if !anyDomain.Matches(domain) {
			t.Errorf("catch-all rule did not match %q", domain)
		}
	}

	singleLabel := make(DomainRuleIndex)
	if err := singleLabel.insert("*"); err != nil {
		t.Fatalf("insert single-label wildcard: %v", err)
	}
	if !singleLabel.Matches("localhost") || singleLabel.Matches("example.com") || singleLabel.Matches("a.example.com") {
		t.Error("`*` should match only one-label domains")
	}
}

func TestConfigNegatedDomainAndCIDRRules(t *testing.T) {
	rules := []string{"!safe.example.com;deny", "safe.example.com;bypass", "+.example.com;redirect", "!10.0.0.0/8;deny", "10.0.0.0/8;bypass"}
	config := &Config{Rules: &rules}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	if config.ResolveDomain("safe.example.com") != RuleBypass || config.ResolveDomain("unsafe.example.com") != RuleDeny {
		t.Error("negated rule or first-match ordering produced an unexpected domain action")
	}
	if !config.MatchDenyAddr(netip.MustParseAddr("192.0.2.1")) || config.ResolveAddr(netip.MustParseAddr("10.1.3.4")) != RuleBypass {
		t.Error("CIDR negation did not match the complement before the positive CIDR")
	}

	orderedRules := []string{"+.blocked.example;bypass", "+.blocked.example;deny"}
	orderedConfig := &Config{Rules: &orderedRules}
	if err := orderedConfig.ParseRules(); err != nil {
		t.Fatalf("ParseRules() with ordered rules error = %v", err)
	}
	if orderedConfig.ResolveDomain("www.blocked.example") != RuleBypass {
		t.Error("first matching rule did not take precedence")
	}
}
