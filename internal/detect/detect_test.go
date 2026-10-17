package detect

import (
	"reflect"
	"testing"
)

func TestParseModalCommands(t *testing.T) {
	text := `
modal token set --token-id ak-EXAMPLEID123 --token-secret as-EXAMPLESECRET456 --profile=karthik
modal profile activate karthik
`
	got := Parse(text)
	want := []Suggestion{
		{Name: "MODAL_TOKEN_ID", Value: "ak-EXAMPLEID123", Service: "modal", Sensitive: true, Source: "modal token set"},
		{Name: "MODAL_TOKEN_SECRET", Value: "as-EXAMPLESECRET456", Service: "modal", Sensitive: true, Source: "modal token set"},
		{Name: "MODAL_PROFILE", Value: "karthik", Service: "modal", Sensitive: false, Source: "modal profile activate"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestParseModalFlagVariants(t *testing.T) {
	text := `modal token set --token-id=ak-X --token-secret as-Y`
	got := Parse(text)
	if len(got) != 2 || got[0].Name != "MODAL_TOKEN_ID" || got[1].Name != "MODAL_TOKEN_SECRET" {
		t.Fatalf("unexpected: %+v", got)
	}
	if !got[0].Sensitive || !got[1].Sensitive {
		t.Fatalf("modal tokens must be sensitive: %+v", got)
	}
}

func TestParseAWSAndEnv(t *testing.T) {
	text := `
aws configure set aws_access_key_id AKIAEXAMPLE
aws configure set aws_secret_access_key exampleSecret
aws configure set region us-east-1
export STRIPE_API_KEY="sk_live_example"
OPENAI_MODEL=gpt-6
DATABASE_URL=postgres://localhost/app
`
	got := Parse(text)
	byName := map[string]Suggestion{}
	for _, s := range got {
		byName[s.Name] = s
	}
	checks := []struct {
		name      string
		service   string
		sensitive bool
	}{
		{"AWS_ACCESS_KEY_ID", "aws", true},
		{"AWS_SECRET_ACCESS_KEY", "aws", true},
		{"AWS_REGION", "aws", false},
		{"STRIPE_API_KEY", "stripe", true},
		{"OPENAI_MODEL", "openai", false},
		{"DATABASE_URL", "", false},
	}
	for _, c := range checks {
		s, ok := byName[c.name]
		if !ok {
			t.Errorf("%s missing", c.name)
			continue
		}
		if s.Service != c.service || s.Sensitive != c.sensitive {
			t.Errorf("%s = service %q sensitive %v, want %q %v", c.name, s.Service, s.Sensitive, c.service, c.sensitive)
		}
	}
	if byName["STRIPE_API_KEY"].Value != "sk_live_example" {
		t.Errorf("quotes not stripped: %q", byName["STRIPE_API_KEY"].Value)
	}
}

func TestParseSkipsPlaceholdersAndDeduplicates(t *testing.T) {
	text := `
API_KEY=<your-key>
SECOND_KEY=changeme
MODAL_TOKEN_ID=ak-1
MODAL_TOKEN_ID=ak-2
`
	got := Parse(text)
	if len(got) != 1 {
		t.Fatalf("want 1 suggestion, got %+v", got)
	}
	if got[0].Name != "MODAL_TOKEN_ID" || got[0].Value != "ak-2" {
		t.Fatalf("dedupe wrong: %+v", got[0])
	}
}

func TestParseBareValues(t *testing.T) {
	text := `
mkarthikprakash919@gmail.com
https://api.example.com/v1
sk-EXAMPLETOKEN1234567890
just some prose that is not a value
`
	got := Parse(text)
	if len(got) != 3 {
		t.Fatalf("want 3 suggestions, got %+v", got)
	}
	if got[0].Name != "EMAIL" || got[0].Sensitive || got[0].Value != "mkarthikprakash919@gmail.com" {
		t.Errorf("email = %+v", got[0])
	}
	if got[1].Name != "BASE_URL" || got[1].Sensitive {
		t.Errorf("url = %+v", got[1])
	}
	if got[2].Name != "API_TOKEN" || !got[2].Sensitive {
		t.Errorf("token = %+v", got[2])
	}
	if parseBareValueCount("a short phrase with spaces") != 0 {
		t.Error("prose should not be detected")
	}
}

func parseBareValueCount(text string) int {
	count := 0
	parseBareValue(text, func(Suggestion) { count++ })
	return count
}
