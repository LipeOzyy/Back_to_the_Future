package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type color struct{}

const (
	red    = "\033[91m"
	green  = "\033[92m"
	yellow = "\033[93m"
	cyan   = "\033[96m"
	bold   = "\033[1m"
	reset  = "\033[0m"
)

func info(msg string)   { fmt.Printf("%s[*]%s %s\n", cyan, reset, msg) }
func ok(msg string)     { fmt.Printf("%s[+]%s %s\n", green, reset, msg) }
func warn(msg string)   { fmt.Printf("%s[!]%s %s\n", yellow, reset, msg) }
func errMsg(msg string) { fmt.Printf("%s[x]%s %s\n", red, reset, msg) }
func title(msg string) {
	line := strings.Repeat("-", 60)
	fmt.Printf("\n%s%s%s\n  %s\n%s%s\n", bold, cyan, line, msg, line, reset)
}

var sensitivePatterns = map[string][]string{
	"config_files": {
		`\.env$`, `\.env\.\w+$`, `wp-config\.php`, `config\.php`,
		`config\.yml$`, `config\.yaml$`, `settings\.py$`, `local\.settings`,
		`application\.properties$`, `appsettings\.json$`, `web\.config$`,
		`\.htaccess$`, `\.htpasswd$`, `database\.yml$`, `secrets\.yml$`,
		`\.npmrc$`, `\.dockerignore$`, `docker-compose\.yml$`,
	},
	"credentials": {
		`password`, `passwd`, `pwd`, `credentials?`, `secret[s_-]`,
		`api[-_]?key`, `access[-_]?token`, `auth[-_]?token`, `bearer`,
		`private[-_]?key`, `client[-_]?secret`, `oauth`, `jwt`,
	},
	"backup_dumps": {
		`\.sql$`, `\.sql\.gz$`, `\.bak$`, `\.backup$`, `\.dump$`,
		`backup`, `dump`, `export`, `db[-_]?backup`,
		`\.zip$`, `\.tar\.gz$`, `\.tar\.bz2$`, `\.7z$`, `\.rar$`,
		`\.tgz$`, `\.gz$`,
	},
	"keys_certs": {
		`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`,
		`\.pem$`, `\.key$`, `\.p12$`, `\.pfx$`, `\.crt$`, `\.cer$`,
		`\.ppk$`, `private[-_]?key`,
	},
	"source_code": {
		`\.git/`, `\.svn/`, `\.hg/`, `\.bzr/`,
		`\.DS_Store$`, `Thumbs\.db$`,
		`composer\.(json|lock)$`, `package\.json$`, `yarn\.lock$`,
		`Gemfile(\.lock)?$`, `requirements\.txt$`, `Pipfile(\.lock)?$`,
	},
	"logs_debug": {
		`\.log$`, `error\.log`, `debug\.log`, `access\.log`,
		`debug=`, `debug=true`, `test\.php`, `info\.php`,
		`phpinfo`, `\.phps$`,
	},
}

var sensitiveOrder = []string{
	"config_files",
	"credentials",
	"backup_dumps",
	"keys_certs",
	"source_code",
	"logs_debug",
}

var vulnParamPatterns = map[string][]string{
	"open_redirect": {
		"redirect", "redirect_to", "redirect_url", "next", "url", "return",
		"returnto", "return_to", "goto", "link", "target", "redir",
		"destination", "dest", "forward", "continue",
	},
	"lfi_rfi": {
		"file", "path", "page", "include", "template", "lang", "language",
		"dir", "folder", "load", "read", "fetch", "document", "root",
		"pg", "style", "pdf", "layout", "conf", "show",
	},
	"ssrf": {
		"url", "uri", "src", "source", "href", "data", "host", "site",
		"endpoint", "proxy", "callback", "image_url", "img_url", "webhook",
		"fetch", "load", "service", "server",
	},
	"sqli": {
		"id", "user", "username", "name", "pid", "cat", "category",
		"item", "product", "ref", "order", "sort", "num", "search",
		"query", "q", "keyword", "filter", "type", "status",
	},
	"xss": {
		"search", "q", "query", "s", "term", "keyword", "name", "title",
		"text", "message", "content", "comment", "input", "value",
		"msg", "description", "data",
	},
	"ssti": {
		"template", "view", "page", "layout", "theme", "render",
		"name", "title", "content",
	},
	"cmd_injection": {
		"cmd", "exec", "command", "run", "ping", "host", "ip",
		"lookup", "nslookup", "dig", "shell",
	},
	"upload": {
		"upload", "file", "image", "avatar", "photo", "attachment",
		"document", "media", "import",
	},
}

var vulnOrder = []string{
	"open_redirect",
	"lfi_rfi",
	"ssrf",
	"sqli",
	"xss",
	"ssti",
	"cmd_injection",
	"upload",
}

var interestingPaths = []string{
	`/admin`, `/administrator`, `/wp-admin`, `/wp-login`,
	`/login`, `/signin`, `/logout`, `/register`, `/signup`,
	`/api/`, `/v1/`, `/v2/`, `/v3/`, `/graphql`, `/swagger`,
	`/openapi`, `/api-docs`, `/redoc`, `/_api`,
	`/debug`, `/test`, `/dev`, `/staging`, `/beta`,
	`/console`, `/phpmyadmin`, `/adminer`, `/cpanel`,
	`/server-status`, `/server-info`, `/\.git/`, `/\.svn/`,
	`/actuator`, `/metrics`, `/health`, `/env`, `/trace`,
	`/dashboard`, `/panel`, `/manage`, `/management`,
	`/config`, `/setup`, `/install`, `/update`,
	`/upload`, `/uploads`, `/files`, `/backup`,
	`/internal`, `/private`, `/secret`, `/hidden`,
}

var staticExtensions = map[string]bool{
	"jpg": true, "jpeg": true, "png": true, "gif": true, "webp": true,
	"svg": true, "ico": true, "bmp": true, "tiff": true,
	"woff": true, "woff2": true, "ttf": true, "eot": true, "otf": true,
	"mp3": true, "mp4": true, "avi": true, "mov": true, "wmv": true,
	"flv": true, "ogg": true, "wav": true,
	"css": true, "map": true,
}

var jsExtensions = map[string]bool{
	"js": true, "jsx": true, "ts": true, "tsx": true, "mjs": true, "cjs": true,
}

type record struct {
	Timestamp string `json:"timestamp"`
	URL       string `json:"url"`
	Status    string `json:"status"`
	MimeType  string `json:"mimetype"`
}

type vulnItem struct {
	URL    string   `json:"url"`
	Params []string `json:"params"`
}

type secretFinding struct {
	Type    string   `json:"type"`
	Source  string   `json:"source"`
	Matches []string `json:"matches"`
}

type probeResult struct {
	URL  string
	Code int
	Size int64
}

type statItem struct {
	Name  string
	Count int
}

type options struct {
	Domain         string
	Subdomains     bool
	Probe          bool
	ProbeSensitive bool
	Limit          int
	Threads        int
	Timeout        int
	CommonCrawl    bool
	Output         string
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Wayback Machine Recon Tool - Pentest & Bug Bounty\n\n")
	fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
	fmt.Fprintf(flag.CommandLine.Output(), "  %s -d target.com [options]\n\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
	flag.PrintDefaults()
	fmt.Fprintf(flag.CommandLine.Output(), "\nExemplos:\n")
	fmt.Fprintf(flag.CommandLine.Output(), "  %s -d target.com\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "  %s -d target.com --subdomains --probe\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "  %s -d target.com --limit 10000 --threads 30\n", os.Args[0])
}

func parseOptions() options {
	var opts options
	flag.StringVar(&opts.Domain, "d", "", "Dominio alvo (ex: target.com)")
	flag.StringVar(&opts.Domain, "domain", "", "Dominio alvo (ex: target.com)")
	flag.BoolVar(&opts.Subdomains, "subdomains", false, "Incluir subdominios (*.target.com)")
	flag.BoolVar(&opts.Probe, "probe", false, "Probar URLs ativas com HTTP requests")
	flag.BoolVar(&opts.ProbeSensitive, "probe-sensitive", false, "Probar apenas arquivos sensiveis")
	flag.IntVar(&opts.Limit, "limit", 50000, "Limite de URLs a coletar")
	flag.IntVar(&opts.Threads, "threads", 20, "Threads para probe")
	flag.IntVar(&opts.Timeout, "timeout", 15, "Timeout HTTP em segundos")
	flag.BoolVar(&opts.CommonCrawl, "common-crawl", false, "Incluir Common Crawl como fonte extra")
	flag.StringVar(&opts.Output, "o", "", "Diretorio de saida")
	flag.StringVar(&opts.Output, "output", "", "Diretorio de saida")
	flag.Usage = usage
	flag.Parse()

	if opts.Domain == "" {
		flag.Usage()
		os.Exit(2)
	}
	if opts.Threads <= 0 {
		opts.Threads = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15
	}
	return opts
}

func normalizeTarget(input string) string {
	target := strings.TrimSpace(input)
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimRight(target, "/")
	return target
}

func makeClient(timeout int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}
}

func doRequestWithRetry(client *http.Client, req *http.Request) (*http.Response, error) {
	var lastErr error
	retryStatuses := map[int]bool{429: true, 500: true, 502: true, 503: true, 504: true}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		cloned := req.Clone(req.Context())
		resp, err := client.Do(cloned)
		if err != nil {
			lastErr = err
			continue
		}
		if !retryStatuses[resp.StatusCode] {
			return resp, nil
		}
		lastErr = fmt.Errorf("status %d", resp.StatusCode)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return nil, lastErr
}

func fetchWaybackURLs(client *http.Client, target string, includeSubdomains bool, limit int) []record {
	query := target + "/*"
	if includeSubdomains {
		query = "*." + target + "/*"
	}

	params := url.Values{}
	params.Set("url", query)
	params.Set("output", "json")
	params.Set("fl", "timestamp,original,statuscode,mimetype")
	params.Set("collapse", "urlkey")
	params.Set("filter", "statuscode:200")
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}

	apiURL := "http://web.archive.org/cdx/search/cdx?" + params.Encode()
	info("Consultando Wayback CDX API para: " + query)

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		errMsg("Erro ao montar request Wayback: " + err.Error())
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityResearcher/1.0)")

	resp, err := doRequestWithRetry(client, req)
	if err != nil {
		errMsg("Erro ao consultar Wayback: " + err.Error())
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg(fmt.Sprintf("Erro ao consultar Wayback: HTTP %d", resp.StatusCode))
		return nil
	}

	var data [][]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		errMsg("Erro ao decodificar JSON do Wayback: " + err.Error())
		return nil
	}

	if len(data) <= 1 {
		warn("Nenhuma URL encontrada no Wayback para este alvo.")
		return nil
	}

	results := make([]record, 0, len(data)-1)
	for _, row := range data[1:] {
		if len(row) < 4 {
			continue
		}
		results = append(results, record{
			Timestamp: row[0],
			URL:       row[1],
			Status:    row[2],
			MimeType:  row[3],
		})
	}
	ok(fmt.Sprintf("%d URLs coletadas do Wayback.", len(results)))
	return results
}

func fetchAlsoGAUStyle(client *http.Client, target string) map[string]bool {
	urls := make(map[string]bool)
	ccURL := fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=%s/*&output=json&limit=5000", url.QueryEscape(target))

	req, err := http.NewRequest(http.MethodGet, ccURL, nil)
	if err != nil {
		return urls
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityResearcher/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return urls
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)
	for scanner.Scan() {
		var obj map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &obj); err != nil {
			continue
		}
		if raw, ok := obj["url"].(string); ok && raw != "" {
			urls[raw] = true
		}
	}

	if len(urls) > 0 {
		ok(fmt.Sprintf("%d URLs extras via Common Crawl.", len(urls)))
	}
	return urls
}

func getExtension(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	ext := strings.TrimPrefix(path.Ext(parsed.Path), ".")
	return strings.ToLower(ext)
}

func isStatic(rawURL string) bool {
	return staticExtensions[getExtension(rawURL)]
}

func isJS(rawURL string) bool {
	return jsExtensions[getExtension(rawURL)]
}

func classifyURL(rawLower string) []string {
	var found []string
	for _, category := range sensitiveOrder {
		for _, pattern := range sensitivePatterns[category] {
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				continue
			}
			if re.FindStringIndex(rawLower) != nil {
				found = append(found, category)
				break
			}
		}
	}
	return found
}

func analyzeParams(rawURL string) map[string][]string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RawQuery == "" {
		return map[string][]string{}
	}

	params, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return map[string][]string{}
	}
	if len(params) == 0 {
		return map[string][]string{}
	}

	hits := make(map[string][]string)
	for param := range params {
		paramLower := strings.ToLower(param)
		for _, vulnType := range vulnOrder {
			for _, keyword := range vulnParamPatterns[vulnType] {
				if paramLower == keyword || strings.Contains(paramLower, keyword) {
					hits[vulnType] = append(hits[vulnType], param)
					break
				}
			}
		}
	}
	for vulnType := range hits {
		sort.Strings(hits[vulnType])
	}
	return hits
}

func findInterestingPaths(rawURL string) []string {
	rawLower := strings.ToLower(rawURL)
	var found []string
	for _, pattern := range interestingPaths {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.FindStringIndex(rawLower) != nil {
			found = append(found, pattern)
		}
	}
	return found
}

func extractSubdomains(urls []string, baseDomain string) []string {
	pattern := regexp.MustCompile(`(?i)https?://([a-z0-9._-]+\.` + regexp.QuoteMeta(baseDomain) + `)`)
	seen := make(map[string]bool)
	for _, rawURL := range urls {
		match := pattern.FindStringSubmatch(rawURL)
		if len(match) > 1 {
			sub := match[1]
			if sub != baseDomain {
				seen[sub] = true
			}
		}
	}
	return sortedKeys(seen)
}

func extractJSURLs(urls []string) []string {
	var js []string
	for _, rawURL := range urls {
		if isJS(rawURL) {
			js = append(js, rawURL)
		}
	}
	return js
}

func extractSecretsRegex(content string, source string) []secretFinding {
	patterns := []struct {
		name    string
		pattern string
	}{
		{"AWS Key", `AKIA[0-9A-Z]{16}`},
		{"AWS Secret", `(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`},
		{"Google API Key", `AIza[0-9A-Za-z\-_]{35}`},
		{"GitHub Token", `ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}`},
		{"JWT", `eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+`},
		{"Private Key", `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`},
		{"Slack Token", `xox[baprs]-[0-9a-zA-Z]{10,48}`},
		{"Generic Secret", `(?i)(secret|token|password|passwd|api_key|apikey)['"\s:=]+['"]([a-zA-Z0-9_\-.]{8,64})['"]`},
		{"Basic Auth in URL", `https?://[a-zA-Z0-9_\-.]+:[a-zA-Z0-9_\-.@!#$%]+@`},
	}

	var findings []secretFinding
	for _, item := range patterns {
		re, err := regexp.Compile(item.pattern)
		if err != nil {
			continue
		}
		matches := re.FindAllString(content, -1)
		if len(matches) > 0 {
			if len(matches) > 5 {
				matches = matches[:5]
			}
			findings = append(findings, secretFinding{
				Type:    item.name,
				Source:  source,
				Matches: matches,
			})
		}
	}
	return findings
}

func probeURL(client *http.Client, rawURL string, timeout int) probeResult {
	req, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityResearcher/1.0)")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			return probeResult{URL: rawURL, Code: resp.StatusCode, Size: resp.ContentLength}
		}
	}

	req, err = http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return probeResult{URL: rawURL, Code: 0, Size: 0}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityResearcher/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return probeResult{URL: rawURL, Code: 0, Size: 0}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return probeResult{URL: rawURL, Code: resp.StatusCode, Size: 0}
}

func probeURLsParallel(client *http.Client, urls []string, maxWorkers int, delay time.Duration) []probeResult {
	jobs := make(chan string)
	results := make(chan probeResult)
	var wg sync.WaitGroup

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rawURL := range jobs {
				result := probeURL(client, rawURL, 10)
				if result.Code != 0 && result.Code != 404 && result.Code != 410 && result.Code != 403 {
					results <- result
				}
				time.Sleep(delay)
			}
		}()
	}

	go func() {
		for _, rawURL := range urls {
			jobs <- rawURL
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var collected []probeResult
	for result := range results {
		collected = append(collected, result)
	}
	return collected
}

func writeReport(outdir string, target string, stats []statItem) (string, error) {
	reportPath := path.Join(outdir, "REPORT.md")
	now := time.Now().Format("2006-01-02 15:04:05")

	lines := []string{
		"# Wayback Recon Report",
		"",
		fmt.Sprintf("**Target:** `%s`  ", target),
		fmt.Sprintf("**Date:** %s  ", now),
		"**Tool:** wayback_recon.go  ",
		"",
		"---",
		"",
		"## Summary",
		"",
		"| Category | Count |",
		"|----------|-------|",
	}

	for _, item := range stats {
		lines = append(lines, fmt.Sprintf("| %s | %d |", item.Name, item.Count))
	}

	lines = append(lines,
		"",
		"---",
		"",
		"## Output Files",
		"",
		"| File | Description |",
		"|------|-------------|",
		"| `all_urls.txt` | Todas as URLs coletadas |",
		"| `endpoints.txt` | Endpoints (sem assets estaticos) |",
		"| `parameters.txt` | URLs com parametros GET |",
		"| `sensitive.txt` | Arquivos possivelmente sensiveis |",
		"| `suspicious.txt` | Caminhos suspeitos/admin |",
		"| `js_files.txt` | Arquivos JavaScript |",
		"| `subdomains.txt` | Subdominios descobertos |",
		"| `vuln_params.json` | Parametros categorizados por vetor |",
		"| `secrets_found.json` | Possiveis segredos encontrados |",
		"| `active_urls.txt` | URLs ativas (se probe foi executado) |",
		"",
		"---",
		"",
		"## Next Steps",
		"",
		"1. Analise `sensitive.txt` e tente acessar via Wayback: `https://web.archive.org/web/*/URL`",
		"2. Teste parametros em `vuln_params.json` com Burp/ffuf/nuclei",
		"3. Execute `getJS` ou `LinkFinder` nos arquivos em `js_files.txt`",
		"4. Use `subdomains.txt` como input para subfinder/amass",
		"5. Passe `endpoints.txt` no `nuclei -l` com templates de CVEs",
	)

	return reportPath, os.WriteFile(reportPath, []byte(strings.Join(lines, "\n")), 0644)
}

func writeLines(filename string, lines []string) error {
	return os.WriteFile(filename, []byte(strings.Join(lines, "\n")), 0644)
}

func writeJSON(filename string, value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool)
	for _, value := range values {
		seen[value] = true
	}
	return sortedKeys(seen)
}

func firstN(values []string, n int) []string {
	if len(values) <= n {
		return values
	}
	return values[:n]
}

func main() {
	opts := parseOptions()
	target := normalizeTarget(opts.Domain)
	outdir := opts.Output
	if outdir == "" {
		outdir = "wayback-" + target
	}

	if err := os.MkdirAll(outdir, 0755); err != nil {
		errMsg("Erro ao criar diretorio de saida: " + err.Error())
		os.Exit(1)
	}

	client := makeClient(opts.Timeout)

	title("Wayback Recon - " + target)
	fmt.Printf("  Saida:       %s/\n", outdir)
	if opts.Subdomains {
		fmt.Printf("  Subdominios: Sim\n")
	} else {
		fmt.Printf("  Subdominios: Nao\n")
	}
	if opts.Probe {
		fmt.Printf("  Probe HTTP:  Sim\n")
	} else {
		fmt.Printf("  Probe HTTP:  Nao\n")
	}
	fmt.Printf("  Limite URLs: %d\n\n", opts.Limit)

	title("1. Coletando URLs")
	records := fetchWaybackURLs(client, target, opts.Subdomains, opts.Limit)

	extraURLs := make(map[string]bool)
	if opts.CommonCrawl {
		extraURLs = fetchAlsoGAUStyle(client, target)
	}

	allMap := make(map[string]bool)
	for _, rec := range records {
		allMap[rec.URL] = true
	}
	for rawURL := range extraURLs {
		allMap[rawURL] = true
	}

	allURLs := sortedKeys(allMap)
	if err := writeLines(path.Join(outdir, "all_urls.txt"), allURLs); err != nil {
		errMsg("Erro ao escrever all_urls.txt: " + err.Error())
		os.Exit(1)
	}
	ok(fmt.Sprintf("Total de URLs unicas: %d", len(allURLs)))

	if len(allURLs) == 0 {
		errMsg("Nenhuma URL para analisar. Verifique o dominio.")
		os.Exit(1)
	}

	title("2. Filtrando Endpoints")
	var endpoints []string
	for _, rawURL := range allURLs {
		if !isStatic(rawURL) {
			endpoints = append(endpoints, rawURL)
		}
	}
	if err := writeLines(path.Join(outdir, "endpoints.txt"), endpoints); err != nil {
		errMsg("Erro ao escrever endpoints.txt: " + err.Error())
		os.Exit(1)
	}
	ok(fmt.Sprintf("Endpoints: %d", len(endpoints)))

	jsFiles := extractJSURLs(allURLs)
	if err := writeLines(path.Join(outdir, "js_files.txt"), jsFiles); err != nil {
		errMsg("Erro ao escrever js_files.txt: " + err.Error())
		os.Exit(1)
	}
	ok(fmt.Sprintf("Arquivos JS: %d", len(jsFiles)))

	title("3. Deteccao de Arquivos Sensiveis")
	sensitiveHits := make(map[string][]string)
	for _, rawURL := range allURLs {
		categories := classifyURL(strings.ToLower(rawURL))
		for _, category := range categories {
			sensitiveHits[category] = append(sensitiveHits[category], rawURL)
		}
	}

	var sensitiveRaw []string
	for _, urls := range sensitiveHits {
		sensitiveRaw = append(sensitiveRaw, urls...)
	}
	allSensitive := uniqueSorted(sensitiveRaw)
	if err := writeLines(path.Join(outdir, "sensitive.txt"), allSensitive); err != nil {
		errMsg("Erro ao escrever sensitive.txt: " + err.Error())
		os.Exit(1)
	}

	sensitiveDetail := make(map[string][]string)
	for category, urls := range sensitiveHits {
		sensitiveDetail[category] = uniqueSorted(urls)
	}
	if err := writeJSON(path.Join(outdir, "sensitive_categorized.json"), sensitiveDetail); err != nil {
		errMsg("Erro ao escrever sensitive_categorized.json: " + err.Error())
		os.Exit(1)
	}
	ok(fmt.Sprintf("Arquivos sensiveis: %d", len(allSensitive)))
	for _, category := range sensitiveOrder {
		if urls, exists := sensitiveHits[category]; exists {
			warn(fmt.Sprintf("  [%s] - %d arquivos", category, len(uniqueSorted(urls))))
		}
	}

	title("4. Analise de Parametros Vulneraveis")
	var urlsWithParams []string
	for _, rawURL := range allURLs {
		if strings.Contains(rawURL, "?") && strings.Contains(rawURL, "=") {
			urlsWithParams = append(urlsWithParams, rawURL)
		}
	}
	sort.Strings(urlsWithParams)
	if err := writeLines(path.Join(outdir, "parameters.txt"), urlsWithParams); err != nil {
		errMsg("Erro ao escrever parameters.txt: " + err.Error())
		os.Exit(1)
	}
	ok(fmt.Sprintf("URLs com parametros: %d", len(urlsWithParams)))

	vulnMap := make(map[string][]vulnItem)
	for _, rawURL := range urlsWithParams {
		hits := analyzeParams(rawURL)
		for _, vulnType := range vulnOrder {
			if params, exists := hits[vulnType]; exists {
				vulnMap[vulnType] = append(vulnMap[vulnType], vulnItem{
					URL:    rawURL,
					Params: params,
				})
			}
		}
	}

	if err := writeJSON(path.Join(outdir, "vuln_params.json"), vulnMap); err != nil {
		errMsg("Erro ao escrever vuln_params.json: " + err.Error())
		os.Exit(1)
	}
	for _, vulnType := range vulnOrder {
		if items, exists := vulnMap[vulnType]; exists {
			ok(fmt.Sprintf("  [%s] - %d URLs candidatas", vulnType, len(items)))
		}
	}

	vulnDir := path.Join(outdir, "vuln_by_type")
	if err := os.MkdirAll(vulnDir, 0755); err != nil {
		errMsg("Erro ao criar vuln_by_type: " + err.Error())
		os.Exit(1)
	}
	for vulnType, items := range vulnMap {
		var urls []string
		for _, item := range items {
			urls = append(urls, item.URL)
		}
		if err := writeLines(path.Join(vulnDir, vulnType+".txt"), urls); err != nil {
			errMsg("Erro ao escrever arquivo de vetor: " + err.Error())
			os.Exit(1)
		}
	}

	title("5. Caminhos Suspeitos / Admin Panels")
	var suspiciousRaw []string
	for _, rawURL := range allURLs {
		if len(findInterestingPaths(rawURL)) > 0 {
			suspiciousRaw = append(suspiciousRaw, rawURL)
		}
	}
	suspicious := uniqueSorted(suspiciousRaw)
	if err := writeLines(path.Join(outdir, "suspicious.txt"), suspicious); err != nil {
		errMsg("Erro ao escrever suspicious.txt: " + err.Error())
		os.Exit(1)
	}
	ok(fmt.Sprintf("Caminhos suspeitos: %d", len(suspicious)))

	title("6. Subdominios Descobertos")
	subdomains := extractSubdomains(allURLs, target)
	if err := writeLines(path.Join(outdir, "subdomains.txt"), subdomains); err != nil {
		errMsg("Erro ao escrever subdomains.txt: " + err.Error())
		os.Exit(1)
	}
	ok(fmt.Sprintf("Subdominios unicos: %d", len(subdomains)))
	for _, subdomain := range firstN(subdomains, 20) {
		fmt.Printf("   - %s\n", subdomain)
	}
	if len(subdomains) > 20 {
		fmt.Printf("   ... e mais %d\n", len(subdomains)-20)
	}

	title("7. Busca por Secrets / Tokens nas URLs")
	var allSecrets []secretFinding
	for _, rawURL := range allURLs {
		allSecrets = append(allSecrets, extractSecretsRegex(rawURL, "url")...)
	}
	if err := writeJSON(path.Join(outdir, "secrets_found.json"), allSecrets); err != nil {
		errMsg("Erro ao escrever secrets_found.json: " + err.Error())
		os.Exit(1)
	}
	if len(allSecrets) > 0 {
		warn(fmt.Sprintf("Possiveis secrets encontrados nas URLs: %d", len(allSecrets)))
		for _, secret := range firstSecrets(allSecrets, 10) {
			warn(fmt.Sprintf("  [%s] em %s", secret.Type, secret.Source))
		}
	} else {
		ok("Nenhum secret obvio nas URLs (verifique JS files manualmente)")
	}

	var activeResults []probeResult
	if opts.Probe || opts.ProbeSensitive {
		title("8. Probe HTTP de URLs")
		probeTargets := endpoints
		if opts.ProbeSensitive {
			probeTargets = allSensitive
		}
		probeTargets = uniqueSorted(probeTargets)
		if len(probeTargets) > 2000 {
			probeTargets = probeTargets[:2000]
		}
		warn(fmt.Sprintf("Probando %d URLs com %d threads...", len(probeTargets), opts.Threads))
		warn("Isso pode demorar. Interrompa com Ctrl+C se necessario.")
		activeResults = probeURLsParallel(client, probeTargets, opts.Threads, 100*time.Millisecond)
		var activeURLs []string
		for _, result := range activeResults {
			activeURLs = append(activeURLs, result.URL)
		}
		activeURLs = uniqueSorted(activeURLs)
		if err := writeLines(path.Join(outdir, "active_urls.txt"), activeURLs); err != nil {
			errMsg("Erro ao escrever active_urls.txt: " + err.Error())
			os.Exit(1)
		}
		ok(fmt.Sprintf("URLs ativas (2xx/3xx/outros): %d", len(activeURLs)))
	}

	title("9. Gerando Relatorio")
	stats := []statItem{
		{"URLs totais", len(allURLs)},
		{"Endpoints", len(endpoints)},
		{"Arquivos JS", len(jsFiles)},
		{"Arquivos sensiveis", len(allSensitive)},
		{"URLs com parametros", len(urlsWithParams)},
		{"Caminhos suspeitos", len(suspicious)},
		{"Subdominios", len(subdomains)},
		{"Possiveis secrets", len(allSecrets)},
		{"URLs ativas (probe)", len(activeResults)},
	}
	report, err := writeReport(outdir, target, stats)
	if err != nil {
		errMsg("Erro ao escrever REPORT.md: " + err.Error())
		os.Exit(1)
	}

	fmt.Println()
	title("Recon Concluido!")
	for _, item := range stats {
		c := reset
		if item.Count > 0 {
			c = green
		}
		fmt.Printf("  %s%-30s%s %s%d%s\n", c, item.Name, reset, bold, item.Count, reset)
	}
	fmt.Println()
	ok("Relatorio Markdown: " + report)
	ok("Todos os arquivos em: " + outdir + "/")
	fmt.Println()
	fmt.Printf("%sProximos passos sugeridos:%s\n", cyan, reset)
	fmt.Printf("  nuclei -l %s/endpoints.txt -t cves/ -o nuclei_results.txt\n", outdir)
	fmt.Printf("  cat %s/js_files.txt | xargs -I{} sh -c 'node linkfinder.js -i {} -o cli'\n", outdir)
	fmt.Printf("  cat %s/vuln_by_type/open_redirect.txt | qsreplace 'https://evil.com' | httpx\n", outdir)
	fmt.Println()
}

func firstSecrets(values []secretFinding, n int) []secretFinding {
	if len(values) <= n {
		return values
	}
	return values[:n]
}
