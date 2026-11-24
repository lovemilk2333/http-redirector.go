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
	bypassList := []string{".internal", "192.168.0.0/16"}
	config := &Config{RedirectList: &redirectList, BypassList: &bypassList}
	if err := config.ParseRules(); err != nil {
		t.Fatalf("ParseRules() error = %v", err)
	}

	if !config.MatchRedirectDomain("API.Example.Com") || config.MatchRedirectDomain("other.net") {
		t.Fatal("MatchRedirectDomain returned an unexpected result")
	}
	if !config.MatchBypassDomain("printer.internal") || config.MatchBypassDomain("internal") {
		t.Fatal("MatchBypassDomain returned an unexpected result")
	}
	if !config.MatchRedirectAddr(netip.MustParseAddr("10.2.3.4")) || config.MatchRedirectAddr(netip.MustParseAddr("192.168.1.2")) {
		t.Fatal("MatchRedirectAddr returned an unexpected result")
	}
	if !config.MatchBypassAddr(netip.MustParseAddr("192.168.1.2")) || config.MatchBypassAddr(netip.MustParseAddr("10.2.3.4")) {
		t.Fatal("MatchBypassAddr returned an unexpected result")
	}
}
