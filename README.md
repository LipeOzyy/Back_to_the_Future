# Back_to_the_Future
![alt image](/img/Terminator.webp)

This is a passive reconnaissance tool designed for penetration testing, bug bounty engagements, and attack surface analysis using archived historical URLs. It queries public sources such as the Wayback Machine CDX API and, optionally, Common Crawl, normalizes the collected results, and generates separate output files categorized by evidence type to support manual triage, fuzzing, parameter testing, endpoint discovery, and the prioritization of potentially sensitive files.

The purpose of this tool is not to automatically exploit vulnerabilities. Instead, it organizes historical information that may reveal legacy endpoints, forgotten routes, configuration files, backups, interesting parameters, subdomains, administrative paths, and potentially exposed tokens embedded in URLs. The generated results are intended to be reviewed and analyzed by an authorized security professional within the permitted scope of the assessment.

### How it works
The workflow begins with a target domain. The tool builds a query for the Wayback Machine using either the domain/* or *.domain/* format, depending on whether subdomains are included. The CDX API response is processed as JSON, and each valid record is converted into a unique list of URLs. When the Common Crawl option is enabled, the tool also queries the configured public index and merges the discovered URLs into the same result set.

After collection, all URLs are deduplicated and sorted. This baseline dataset is saved as all_urls.txt and serves as the input for the remaining analysis stages. From this dataset, the tool filters endpoints that do not appear to be static assets, identifies JavaScript files, extracts subdomains, detects GET parameters, and classifies URLs containing filenames, extensions, or naming patterns commonly associated with sensitive files.

Sensitive file classification is performed using regular expressions applied to each URL. The analyzed categories include configuration files, credentials, backups, database dumps, cryptographic keys, certificates, version control artifacts, log files, and debug-related files. This stage does not verify whether a file is currently exposed on the target server. Instead, it helps prioritize URLs that may warrant manual validation or further inspection through the Wayback Machine archive.

The parameter analysis examines query string parameter names and maps them to common security testing categories, including open redirect, LFI/RFI, SSRF, SQL injection, XSS, SSTI, command injection, and file upload. This classification is heuristic and does not indicate a confirmed vulnerability. Rather, it highlights candidate parameters that may be evaluated using appropriate testing tools, interception proxies, controlled payloads, or scanner templates.

The tool also searches for administrative and security-relevant paths within the collected URLs, such as login panels, API endpoints, Swagger/OpenAPI documentation, health check endpoints, internal directories, upload paths, backup locations, configuration files, and routes related to development or staging environments. These findings are written to suspicious.txt to simplify manual review.

Optionally, the tool can perform HTTP probes against either all collected endpoints or only those classified as sensitive. It first sends a HEAD request and falls back to GET if necessary. URLs returning status codes other than 404, 410, or 403 are considered active for reconnaissance purposes and are recorded in active_urls.txt. To reduce operational impact, probing is limited to the first 2,000 unique targets after deduplication.

At the end of execution, the tool generates a Markdown report named REPORT.md, summarizing the number of findings in each category and describing the generated output files. This report serves as an operational overview to guide the next steps of the security assessment.

### Generated output
By default, the tool creates an output directory named wayback-DOMAIN. This location can be customized using the -o or --output option.

The all_urls.txt file contains all unique URLs collected during reconnaissance. The endpoints.txt file contains filtered URLs with common static asset extensions, such as images, fonts, videos, CSS files, and source maps, removed. The parameters.txt file contains URLs with query strings and GET parameters. The sensitive.txt file lists URLs classified as potentially sensitive, while sensitive_categorized.json organizes the same findings by category.

The suspicious.txt file contains administrative, internal, or otherwise noteworthy routes identified during analysis. The js_files.txt file lists all discovered JavaScript files. The subdomains.txt file contains subdomains extracted from historical URLs. The vuln_params.json file maps detected parameters to potential testing categories, while the vuln_by_type directory contains separate files for each category to facilitate integration with other security tools. The secrets_found.json file records potential tokens or secrets identified directly within URLs. When HTTP probing is enabled, the active_urls.txt file contains URLs that responded with status codes considered relevant for further investigation.

Compilation

The Go version has no external library dependencies. It relies exclusively on the Go standard library for HTTP requests, JSON processing, regular expressions, concurrency, URL parsing, file operations, and command-line argument parsing.

To compile the tool, run:

```
go build -o wayback_recon machine.go
```
### Usage

The minimum required input is the target domain. The tool automatically creates the output directory, collects historical URLs from the Wayback Machine, performs local analysis, and generates the output files.
```
./wayback_recon -d target.com
```
To include historical subdomains in the collection:
```
./wayback_recon -d target.com --subdomains
```
To perform HTTP probing against the collected endpoints:
```
./wayback_recon -d target.com --probe
```
To probe only URLs classified as sensitive:
```
./wayback_recon -d target.com --probe-sensitive
```
To control the collection size and HTTP probe concurrency:
```
./wayback_recon -d target.com --limit 10000 --threads 30 --timeout 20
```
To include Common Crawl as an additional data source:
```
./wayback_recon -d target.com --common-crawl
```
To specify a custom output directory:
```
./wayback_recon -d target.com -o recon-target
```

### Parameters
| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `-d` ou `--domain` | string | Required | Specifies the target domain. The value should contain only the domain name. If http:// or https:// is provided, the tool automatically removes the scheme before building the archive queries. |
| `--subdomains` | booleano | false | Modifies the Wayback Machine query to include subdomains using the *.domain/* format. This increases the number of collected URLs and broadens the discovery scope. It should only be used when subdomains are within the authorized assessment scope. |
| `--probe` | booleano | falso | Performs HTTP requests against the filtered endpoints to identify those that are still reachable. This feature generates active traffic toward the target and should be used carefully during bug bounty engagements or other sensitive environments. |
| `--probe-sensitive` | booleano | falso | Performs HTTP probing only against URLs classified as potentially sensitive. When enabled, the probe target list is generated from sensitive.txt instead of endpoints.txt. |
| `--limit` | inteiro | `50000` | Specifies the maximum number of records requested from the Wayback Machine. Larger values increase coverage but may also increase response time and output size. |
| `--threads` | inteiro | `20` | Defines the number of concurrent workers used during the HTTP probing phase. This parameter affects only active probing and does not influence passive URL collection. |
| `--timeout` | inteiro | `15` | Sets the HTTP timeout, in seconds, for external requests and HTTP probes. |
| `--common-crawl` | booleano | falso | Enables an additional query against the configured Common Crawl public index. URLs obtained from Common Crawl are merged with the Wayback Machine results before deduplication. |
| `-o` ou `--output` | string | `wayback-DOMINIO` | Specifies the output directory where the generated files will be stored. If the directory does not exist, it is created automatically. |

### Interpreting the results

The generated results should be treated as reconnaissance data rather than confirmed vulnerabilities. A URL listed in sensitive.txt may simply indicate that a sensitive file existed historically and does not necessarily mean it is currently accessible. Likewise, an entry in vuln_params.json indicates that a parameter name is potentially interesting for security testing, but it does not demonstrate exploitability.

In a professional penetration testing workflow, the generated files can serve as inputs for subsequent assessment stages. For example, endpoints.txt can be supplied to scanners or fuzzers, parameters.txt can support manual testing through an interception proxy, js_files.txt can be analyzed with JavaScript endpoint extraction tools, subdomains.txt can complement DNS resolution and active enumeration, and sensitive.txt can guide manual review in the Wayback Machine or controlled validation against the current environment.

### Operational considerations

Collecting data from the Wayback Machine is passive with respect to the target because all information is retrieved from a third-party archive. Enabling the --probe option changes this behavior by sending HTTP requests directly to the discovered hosts. Before performing large-scale probing, ensure that the target, its subdomains, and the intended request volume are all within the authorized scope of the assessment.

The tool relies on heuristics based on filenames, extensions, and commonly observed naming patterns. This approach prioritizes speed and broad coverage, but it may produce both false positives and false negatives. Its primary purpose is to reduce large collections of historical URLs into smaller, actionable datasets that can be reviewed more efficiently during manual analysis.

### Example next steps

After a standard execution, REPORT.md should be reviewed first to understand the overall findings and determine where to focus further investigation. In most cases, sensitive.txt, suspicious.txt, and vuln_params.json provide the most valuable starting points for manual triage.

The following examples demonstrate common integrations with third-party security tools. These commands are not part of tool itself and require the respective tools to be installed separately.
```
nuclei -l wayback-target.com/endpoints.txt -t cves/ -o nuclei_results.txt
```
```
cat wayback-target.com/js_files.txt | xargs -I{} sh -c 'node linkfinder.js -i {} -o cli'
```
```
cat wayback-target.com/vuln_by_type/open_redirect.txt | qsreplace 'https://example.com' | httpx
```

### Disclaimer

This tool is intended for use only in environments you own, authorized penetration testing engagements, bug bounty programs that explicitly permit this type of activity, or other authorized security assessments. The operator is responsible for complying with the authorized scope, rules of engagement, rate-limiting requirements, and all applicable laws and regulations.