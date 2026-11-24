package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestConfigLoaderCreatesDefaultConfig(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.yaml")
	loader := &ConfigLoader{filename: filename}

	if err := loader.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !slices.Equal(*loader.Config().BypassList, DEFAULT_BYPASS_LIST) {
		t.Fatalf("BypassList = %v, want default %v", loader.Config().BypassList, DEFAULT_BYPASS_LIST)
	}
	if loader.Config().RedirectList == nil || len(*loader.Config().RedirectList) != 0 {
		t.Fatalf("RedirectList = %#v, want default empty list", loader.Config().RedirectList)
	}
	if loader.Config().DenyList == nil || len(*loader.Config().DenyList) != 0 {
		t.Fatalf("DenyList = %#v, want default empty list", loader.Config().DenyList)
	}
	if _, err := os.Stat(filename); err != nil {
		t.Fatalf("default config was not saved: %v", err)
	}
}

func TestConfigLoaderPreservesExplicitEmptyBypassList(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(filename, []byte("bypass-list: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loader := &ConfigLoader{filename: filename}

	if err := loader.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loader.Config().BypassList == nil || *loader.Config().BypassList == nil || len(*loader.Config().BypassList) != 0 {
		t.Fatalf("BypassList = %#v, want explicit empty list", loader.Config().BypassList)
	}
	if err := loader.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	reloaded := &ConfigLoader{filename: filename}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload error = %v", err)
	}
	if reloaded.Config().BypassList == nil || *reloaded.Config().BypassList == nil || len(*reloaded.Config().BypassList) != 0 {
		t.Fatalf("reloaded BypassList = %#v, want explicit empty list", reloaded.Config().BypassList)
	}
}

func TestConfigLoaderPreservesExplicitEmptyRedirectList(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(filename, []byte("redirect-list: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loader := &ConfigLoader{filename: filename}

	if err := loader.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loader.Config().RedirectList == nil || *loader.Config().RedirectList == nil || len(*loader.Config().RedirectList) != 0 {
		t.Fatalf("RedirectList = %#v, want explicit empty list", loader.Config().RedirectList)
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
	input := "# project settings\nhttp-port: 0 # disable HTTP\nbypass-list:\n  - 10.0.0.0/8 # private network\n"
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
		"  - 10.0.0.0/8 # private network",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("saved config does not contain %q:\n%s", want, data)
		}
	}
}

func TestConfigBuildsReversedDomainRuleIndexes(t *testing.T) {
	redirectList := []string{"xbox.*.microsoft.com", "+.baidu.com", ".lan"}
	bypassList := []string{"192.168.0.0/16", "WWW.Example.COM"}
	config := &Config{
		RedirectList: &redirectList,
		BypassList:   &bypassList,
	}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	for _, domain := range []string{"xbox.a.microsoft.com", "xbox.b.microsoft.com", "baidu.com", "tieba.baidu.com", "123.tieba.baidu.com", "foo.lan", "a.b.lan"} {
		if !config.RedirectRules.Matches(domain) {
			t.Errorf("RedirectRules.Matches(%q) = false, want true", domain)
		}
	}
	for _, domain := range []string{"xbox.microsoft.com", "a.xbox.b.microsoft.com", "lan"} {
		if config.RedirectRules.Matches(domain) {
			t.Errorf("RedirectRules.Matches(%q) = true, want false", domain)
		}
	}
	if !config.BypassRules.Matches("www.example.com") || !config.BypassRules.Matches("WWW.EXAMPLE.COM.") {
		t.Fatal("domain index should normalize labels to lowercase and ignore a trailing dot")
	}
	if len(config.RedirectCIDRs) != 0 || len(config.BypassCIDRs) != 1 || config.BypassCIDRs[0].String() != "192.168.0.0/16" {
		t.Fatalf("CIDR indexes = redirect %v, bypass %v", config.RedirectCIDRs, config.BypassCIDRs)
	}
	if _, ok := config.RedirectRules["com"].Children["microsoft"].Children["*"]; !ok {
		t.Fatal("domain rules are not stored as a reversed-label index")
	}
}

func TestConfigMatchMethods(t *testing.T) {
	redirectList := []string{"+.example.com", "10.0.0.0/8"}
	denyList := []string{"+.blocked.example", "203.0.113.0/24"}
	bypassList := []string{".internal", "192.168.0.0/16"}
	config := &Config{RedirectList: &redirectList, DenyList: &denyList, BypassList: &bypassList}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	if !config.MatchRedirectDomain("API.Example.Com") || config.MatchRedirectDomain("other.net") {
		t.Fatal("MatchRedirectDomain returned an unexpected result")
	}
	if !config.MatchBypassDomain("printer.internal") || config.MatchBypassDomain("internal") {
		t.Fatal("MatchBypassDomain returned an unexpected result")
	}
	if !config.MatchDenyDomain("www.blocked.example") || config.MatchDenyDomain("example") {
		t.Fatal("MatchDenyDomain returned an unexpected result")
	}
	if !config.MatchRedirectAddr(netip.MustParseAddr("10.2.3.4")) || config.MatchRedirectAddr(netip.MustParseAddr("192.168.1.2")) {
		t.Fatal("MatchRedirectAddr returned an unexpected result")
	}
	if !config.MatchBypassAddr(netip.MustParseAddr("192.168.1.2")) || config.MatchBypassAddr(netip.MustParseAddr("10.2.3.4")) {
		t.Fatal("MatchBypassAddr returned an unexpected result")
	}
	if !config.MatchDenyAddr(netip.MustParseAddr("203.0.113.9")) || config.MatchDenyAddr(netip.MustParseAddr("203.0.114.9")) {
		t.Fatal("MatchDenyAddr returned an unexpected result")
	}
}

func TestEmptyRedirectListDoesNotMatchInvalidDomain(t *testing.T) {
	config := &Config{}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	if !config.MatchRedirectDomain("example.com") {
		t.Error("empty redirect list should match a valid domain")
	}
	for _, domain := range []string{"bad_name.example", strings.Repeat("a", MaxDomainLabelLength+1) + ".com", strings.Repeat("a.", 126) + "aa"} {
		if config.MatchRedirectDomain(domain) {
			t.Errorf("MatchRedirectDomain(%q) = true, want false for invalid domain", domain)
		}
	}
}

func TestRedirectRulesDoNotMatchOtherHostKindsByDefault(t *testing.T) {
	redirectList := []string{"+.example.com"}
	config := &Config{RedirectList: &redirectList}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}
	if config.MatchRedirectAddr(netip.MustParseAddr("203.0.113.1")) {
		t.Error("domain-only redirect list matched an IP address")
	}

	redirectList = []string{"203.0.113.0/24"}
	config = &Config{RedirectList: &redirectList}
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
	redirectList := []string{"+.example.com", "!+.safe.example.com"}
	denyList := []string{"10.0.0.0/8", "!10.1.0.0/16", "+.blocked.example", "!safe.blocked.example"}
	config := &Config{RedirectList: &redirectList, DenyList: &denyList}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	if !config.MatchRedirectDomain("www.example.com") || config.MatchRedirectDomain("safe.example.com") {
		t.Error("redirect negation did not exclude the safe subdomain")
	}
	if !config.MatchDenyDomain("www.blocked.example") || config.MatchDenyDomain("safe.blocked.example") {
		t.Error("deny negation did not exclude the safe domain")
	}
	if !config.MatchDenyAddr(netip.MustParseAddr("10.2.3.4")) || config.MatchDenyAddr(netip.MustParseAddr("10.1.3.4")) {
		t.Error("CIDR negation did not exclude the nested prefix")
	}

	negativeOnly := []string{"!10.0.0.0/8"}
	config = &Config{RedirectList: &negativeOnly}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() with exclusion-only rule error = %v", err)
	}
	if !config.MatchRedirectAddr(netip.MustParseAddr("192.0.2.1")) || config.MatchRedirectAddr(netip.MustParseAddr("10.0.0.1")) {
		t.Error("exclusion-only CIDR list did not match the complement of its excluded prefix")
	}
	if config.MatchRedirectDomain("example.com") {
		t.Error("CIDR rule should not match the domain matcher")
	}
}
