package ioc

import (
	"regexp"
)

// -- Regexes --
// This stemmed from Cacador with some changes and improvements
// https://github.com/sroberts/cacador

// iocRegexes List of regexes corresponding to a IOC
var iocRegexes = map[Type]*regexp.Regexp{
	// Bitcoin
	Bitcoin: regexp.MustCompile(`(?:^|[ '":])((bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39})`),
	// Hashes
	MD5:    regexp.MustCompile(`\b[A-Fa-f0-9]{32}\b`),
	SHA1:   regexp.MustCompile(`\b[A-Fa-f0-9]{40}\b`),
	SHA256: regexp.MustCompile(`\b[A-Fa-f0-9]{64}\b`),
	SHA512: regexp.MustCompile(`\b[A-Fa-f0-9]{128}\b`),
	// Collides with ipv6:  "ssdeep": regexp.MustCompile("\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}"),
	// Domains
	Domain: regexp.MustCompile(`^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$`),
	// Emails
	Email: regexp.MustCompile(`[A-Za-z0-9_\.!#\$%&\*\+-\/=\?\^_\` + "`" + `\{\|\}~]+((\ ?(\[|\()?\ ?@\ ?(\)|\])?\ ?)|(\ ?(\[|\()\ ?[aA][tT]\ ?(\)|\])\ ?))[.0-9a-z-\[\]\(\)\{\}]+`),
	// IPs
	IPv4: regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([\[\(]?\.[\]\)]?)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	IPv6: regexp.MustCompile(`(?:[a-f0-9]{1,4}:|:){2,7}(?:[a-f0-9]{1,4}|:)\b`),
	// URLs
	URL: regexp.MustCompile(`(\b((http|https|hxxp|hxxps|nntp|ntp|rdp|sftp|smtp|ssh|tor|webdav|xmpp)[[([\{]?\:[])]?\/\/[])]?[\S]+)\b\/?)`),
	// Files
	File: regexp.MustCompile(`(([\w\-]+)\.)+(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt|pages|keynote|numbers|exe|dll|jar|flv|swf|jpeg|jpg|gif|png|tiff|bmp|plist|app|pkg|html|htm|php|jsp|asp|zip|zipx|7z|rar|tar|gz)`),
	// Utility
	CVE:   regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`),
	CAPEC: regexp.MustCompile(`(?i)CAPEC-\d+`),
	CWE:   regexp.MustCompile(`(?i)CWE-\d+`),
	// support for URI and WFN CPE 2.2 and 2.3 bindings
	CPE: regexp.MustCompile(`(?i)cpe(:2[.]3)?:[/]?[aoh*\-](:[?*]?([a-z0-9\-._]|([\\][\\?*!"#$%&'()+,/:;<=>@[\]^{|}~])|[%~])*[?*\-]?){0,5}(:([a-z]{2,3}(-([a-z]{2}|[0-9]{3}))?)|[*\-])?(:[?*]?([a-z0-9\-._]|([\\][\\?*!"#$%&'()+,/:;<=>@[\]^{|}~])|[%~])*[?*\-]?){0,5}`),
	// Mitre Classifications
	MitreMatrix:       regexp.MustCompile(`^(?P<concept>(?i)MA)\d{4}(\.\d{3})?$`),
	MitreTactic:       regexp.MustCompile(`^(?P<concept>(?i)TA)\d{4}(\.\d{3})?$`),
	MitreTechnique:    regexp.MustCompile(`^(?P<concept>(?i)T)\d{4}$`),
	MitreSubtechnique: regexp.MustCompile(`^(?P<concept>(?i)T)\d{4}(\.\d{3})$`),
	MitreMitigation:   regexp.MustCompile(`^(?P<concept>(?i)M)\d{4}(\.\d{3})?$`),
	MitreGroup:        regexp.MustCompile(`^(?P<concept>(?i)G)\d{4}(\.\d{3})?$`),
	MitreSoftware:     regexp.MustCompile(`^(?P<concept>(?i)S)\d{4}(\.\d{3})?$`),
	MitreDetection:    regexp.MustCompile(`^(?P<concept>(?i)DS)\d{4}(\.\d{3})?$`),
	// AWS Host Names
	AWSHostName: regexp.MustCompile(`ip-(\d+-)+\d+.*internal`),
	// Godaddy Host Names
	GoDaddyHostName: regexp.MustCompile(`((\w|-)+\.?)+\.gdg`),
}
