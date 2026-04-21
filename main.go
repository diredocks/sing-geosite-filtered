package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-github/v45/github"
	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

var githubClient *github.Client

func init() {
	accessToken, loaded := os.LookupEnv("ACCESS_TOKEN")
	if !loaded {
		githubClient = github.NewClient(nil)
		return
	}
	transport := &github.BasicAuthTransport{
		Username: accessToken,
	}
	githubClient = github.NewClient(transport.Client())
}

func fetch(from string) (*github.RepositoryRelease, error) {
	names := strings.SplitN(from, "/", 2)

	release, _, err := githubClient.Repositories.GetLatestRelease(
		context.Background(),
		names[0],
		names[1],
	)

	return release, err
}

func get(downloadURL *string) ([]byte, error) {
	log.Info("download ", *downloadURL)
	resp, err := http.Get(*downloadURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func download(release *github.RepositoryRelease) ([]byte, error) {
	asset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "dlc.dat"
	})
	checksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "dlc.dat.sha256sum"
	})
	if asset == nil || checksumAsset == nil {
		return nil, E.New("missing asset")
	}

	data, err := get(asset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	sumData, err := get(checksumAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != string(sumData[:64]) {
		return nil, E.New("checksum mismatch")
	}

	return data, nil
}

func parse(data []byte) (map[string][]geosite.Item, error) {
	var list routercommon.GeoSiteList
	if err := proto.Unmarshal(data, &list); err != nil {
		return nil, err
	}

	out := make(map[string][]geosite.Item)

	for _, entry := range list.Entry {
		code := strings.ToLower(entry.CountryCode)

		var domains []geosite.Item
		attributes := make(map[string][]*routercommon.Domain)

		for _, d := range entry.Domain {
			for _, attr := range d.Attribute {
				attributes[attr.Key] = append(attributes[attr.Key], d)
			}

			switch d.Type {
			case routercommon.Domain_Plain:
				domains = append(domains, geosite.Item{Type: geosite.RuleTypeDomainKeyword, Value: d.Value})
			case routercommon.Domain_Regex:
				domains = append(domains, geosite.Item{Type: geosite.RuleTypeDomainRegex, Value: d.Value})
			case routercommon.Domain_RootDomain:
				if strings.Contains(d.Value, ".") {
					domains = append(domains, geosite.Item{Type: geosite.RuleTypeDomain, Value: d.Value})
				}
				domains = append(domains, geosite.Item{Type: geosite.RuleTypeDomainSuffix, Value: "." + d.Value})
			case routercommon.Domain_Full:
				domains = append(domains, geosite.Item{Type: geosite.RuleTypeDomain, Value: d.Value})
			}
		}

		out[code] = common.Uniq(domains)

		for attr, list := range attributes {
			var items []geosite.Item
			for _, d := range list {
				switch d.Type {
				case routercommon.Domain_Plain:
					items = append(items, geosite.Item{Type: geosite.RuleTypeDomainKeyword, Value: d.Value})
				case routercommon.Domain_Regex:
					items = append(items, geosite.Item{Type: geosite.RuleTypeDomainRegex, Value: d.Value})
				case routercommon.Domain_RootDomain:
					if strings.Contains(d.Value, ".") {
						items = append(items, geosite.Item{Type: geosite.RuleTypeDomain, Value: d.Value})
					}
					items = append(items, geosite.Item{Type: geosite.RuleTypeDomainSuffix, Value: "." + d.Value})
				case routercommon.Domain_Full:
					items = append(items, geosite.Item{Type: geosite.RuleTypeDomain, Value: d.Value})
				}
			}
			out[code+"@"+attr] = common.Uniq(items)
		}
	}

	return out, nil
}

type filteredCodePair struct {
	code    string
	badCode string
}

func filterTags(data map[string][]geosite.Item) map[string][]geosite.Item {
	filtered := make(map[string][]geosite.Item)

	var codeList []string
	for k := range data {
		codeList = append(codeList, k)
	}

	var badList []filteredCodePair

	for _, code := range codeList {
		parts := strings.Split(code, "@")
		if len(parts) != 2 {
			continue
		}

		leftParts := strings.Split(parts[0], "-")
		last := leftParts[len(leftParts)-1]

		if last == parts[1] {
			filtered[code] = data[code]
			delete(data, code)
			continue
		}

		if "!"+last == parts[1] || last == "!"+parts[1] {
			badList = append(badList, filteredCodePair{
				code:    parts[0],
				badCode: code,
			})
		}
	}

	for _, it := range badList {
		bad := data[it.badCode]
		if bad == nil {
			continue
		}

		filtered[it.badCode] = bad
		delete(data, it.badCode)

		base, ok := data[it.code]
		if !ok {
			continue
		}

		set := make(map[geosite.Item]bool)
		for _, v := range base {
			set[v] = true
		}
		for _, v := range bad {
			delete(set, v)
		}

		var newList []geosite.Item
		for v := range set {
			newList = append(newList, v)
		}
		data[it.code] = newList
	}

	sort.Strings(codeList)
	return filtered
}

func writeRuleSet(dir, code string, domains []geosite.Item) error {
	rule := geosite.Compile(domains)

	var headless option.DefaultHeadlessRule
	headless.Domain = rule.Domain
	headless.DomainSuffix = rule.DomainSuffix
	headless.DomainKeyword = rule.DomainKeyword
	headless.DomainRegex = rule.DomainRegex

	rs := option.PlainRuleSet{
		Rules: []option.HeadlessRule{
			{
				Type:           C.RuleTypeDefault,
				DefaultOptions: headless,
			},
		},
	}

	path := filepath.Join(dir, "geosite-"+code+".srs")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return srs.Write(f, rs, false)
}

func generate(release *github.RepositoryRelease, output string) error {
	data, err := download(release)
	if err != nil {
		return err
	}

	m, err := parse(data)
	if err != nil {
		return err
	}

	filtered := filterTags(m)

	os.RemoveAll(output)
	if err := os.MkdirAll(output, 0o755); err != nil {
		return err
	}

	for code, domains := range filtered {
		if err := writeRuleSet(output, code, domains); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	release, err := fetch("v2fly/domain-list-community")
	if err != nil {
		log.Fatal(err)
	}

	if err := generate(release, "rule-set-filtered"); err != nil {
		log.Fatal(err)
	}
}
