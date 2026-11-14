package policy

import "testing"

const testService = "secretsmanager.amazonaws.com"

// The keys that come from a service principal replace Context's, in any
// case, and the rest of Context is kept.
func TestServiceContext(t *testing.T) {
	rc := serviceContext(testService, map[string][]string{
		"AWS:PrincipalServiceName":  {"s3.amazonaws.com"},
		"aws:principalisawsservice": {"false"},
		"aws:username":              {"admin"},
		"aws:PrincipalOrgID":        {"o-a1b2c3d4e5"},
		"aws:PrincipalOrgPaths":     {"o-a1b2c3d4e5/r-ab12/"},
		"aws:PrincipalTag/team":     {"ops"},
		"AWS:PRINCIPALTAG/Dept":     {"hr"},
		"aws:SourceArn":             {"arn:aws:secretsmanager:us-east-1:111122223333:secret:s"},
	})
	for key, want := range map[string]string{
		"aws:PrincipalServiceName":  testService,
		"aws:PrincipalIsAWSService": "true",
		"aws:SourceArn":             "arn:aws:secretsmanager:us-east-1:111122223333:secret:s",
	} {
		if v, ok := rc.get(key); !ok || len(v) != 1 || v[0] != want {
			t.Errorf("%s = %v, want [%s]", key, v, want)
		}
	}
	for _, key := range []string{
		"aws:username", "aws:PrincipalOrgID", "aws:PrincipalOrgPaths", "aws:PrincipalTag/team",
		"aws:PrincipalTag/Dept",
	} {
		if v, ok := rc.get(key); ok {
			t.Errorf("%s = %v, want absent", key, v)
		}
	}
}

// The principal keys whose value is undocumented are unknown whatever
// Context gives them, and req.Unknown is not written to.
func TestAuthorizeServiceUnknownKeys(t *testing.T) {
	for _, key := range serviceUnknownKeys {
		p := mustParseResource(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow",`+
			`"Principal":{"Service":"`+testService+`"},"Action":"*","Resource":"*",`+
			`"Condition":{"StringEquals":{"`+key+`":"v"}}}}`)
		// Room for the appended keys, so that writing to it would show.
		backing := make([]string, 1+len(serviceUnknownKeys))
		backing[0] = "k:v"
		unknown := backing[:1]
		got := AuthorizeService(ServiceRequest{
			Action: "lambda:InvokeFunction", Resource: "*", Service: testService,
			Context: map[string][]string{key: {"v"}}, Unknown: unknown,
		}, p)
		if got.Decision != ImplicitDeny {
			t.Errorf("Allow on %s given in Context = %v, want ImplicitDeny", key, got.Decision)
		}
		if backing[1] != "" {
			t.Fatalf("AuthorizeService wrote to the caller's Unknown: %q", backing)
		}
	}
}

func TestServiceMatch(t *testing.T) {
	for _, c := range []struct {
		element string
		want    bool
	}{
		{`"*"`, true},
		{`{"AWS":"*"}`, true},
		{`{"Service":"` + testService + `"}`, true},
		{`{"Service":["s3.amazonaws.com","` + testService + `"]}`, true},
		{`{"Service":"s3.amazonaws.com"}`, false},
		{`{"Service":"SecretsManager.amazonaws.com"}`, false},
		{`{"AWS":"111122223333"}`, false},
		{`{"AWS":"*","Service":"s3.amazonaws.com"}`, true},
		{`{"CanonicalUser":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}`, false},
	} {
		p := mustParseResource(t, resourceDoc("Allow", `"Principal":`+c.element, bucketObjects)).statements[0].principal
		if got := p.serviceMatch(testService); got != c.want {
			t.Errorf("%s serviceMatch = %v, want %v", c.element, got, c.want)
		}
		if got := p.excludesService(testService); got != c.want {
			t.Errorf("%s excludesService = %v, want %v", c.element, got, c.want)
		}
	}
}
