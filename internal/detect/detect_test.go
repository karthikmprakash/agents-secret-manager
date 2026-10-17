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
		{Name: "MODAL_PROFILE", Value: "karthik", Service: "modal", Sensitive: false, Source: "modal token set"},
	}
	for i := range got {
		got[i].ID = ""
		got[i].Line = 0
		got[i].Reason = ""
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

func TestParseSkipsPlaceholdersAndPreservesConflicts(t *testing.T) {
	text := `
API_KEY=<your-key>
SECOND_KEY=changeme
MODAL_TOKEN_ID=ak-1
MODAL_TOKEN_ID=ak-2
`
	got := Parse(text)
	if len(got) != 2 {
		t.Fatalf("want both differing values, got %+v", got)
	}
	if got[0].Value != "ak-1" || got[1].Value != "ak-2" || got[1].Name != "MODAL_TOKEN_ID_2" {
		t.Fatalf("conflict handling wrong: %+v", got)
	}
}

func TestParseBareValues(t *testing.T) {
	text := `
person@example.org
https://api.example.com/v1
sk-EXAMPLETOKEN1234567890
just some prose that is not a value
`
	got := Parse(text)
	if len(got) != 3 {
		t.Fatalf("want 3 suggestions, got %+v", got)
	}
	if got[0].Name != "EMAIL" || got[0].Sensitive || got[0].Value != "person@example.org" {
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

func TestParseCloudflareR2LabeledBlock(t *testing.T) {
	text := `Your API Token cfat_EXAMPLEONLYTOKEN0123456789abcdef
Access Key ID 0123456789abcdef0123456789abcdef
Secret Access Key fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
S3 API endpoint https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com`
	report := Analyze(text)
	if len(report.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", report.Warnings)
	}
	got := report.Suggestions
	want := []struct {
		name      string
		value     string
		sensitive bool
		line      int
	}{
		{"CLOUDFLARE_API_TOKEN", "cfat_EXAMPLEONLYTOKEN0123456789abcdef", true, 1},
		{"R2_ACCESS_KEY_ID", "0123456789abcdef0123456789abcdef", true, 2},
		{"R2_SECRET_ACCESS_KEY", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", true, 3},
		{"R2_ENDPOINT", "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com", false, 4},
	}
	if len(got) != len(want) {
		t.Fatalf("want %d suggestions, got %+v", len(want), got)
	}
	for i, expected := range want {
		if got[i].Name != expected.name || got[i].Value != expected.value {
			t.Errorf("entry %d = %+v", i, got[i])
		}
		if got[i].Service != "cloudflare" {
			t.Errorf("%s service = %q, want cloudflare", got[i].Name, got[i].Service)
		}
		if got[i].Sensitive != expected.sensitive {
			t.Errorf("%s sensitive = %v, want %v", got[i].Name, got[i].Sensitive, expected.sensitive)
		}
		if got[i].Line != expected.line {
			t.Errorf("%s line = %d, want %d", got[i].Name, got[i].Line, expected.line)
		}
	}
}

func TestParseWhitespaceSeparatedLabels(t *testing.T) {
	got := Parse("API Token dummy-token-value-1234567890\nS3 API endpoint https://s3.example.org\nAWS Access Key ID AKIAEXAMPLE123456789\n")
	if len(got) != 3 {
		t.Fatalf("want 3 suggestions, got %+v", got)
	}
	if got[0].Name != "API_TOKEN" || !got[0].Sensitive || got[0].Service != "" {
		t.Errorf("generic API token = %+v", got[0])
	}
	if got[1].Name != "S3_ENDPOINT" || got[1].Sensitive || got[1].Service != "" {
		t.Errorf("generic S3 endpoint = %+v", got[1])
	}
	if got[2].Name != "AWS_ACCESS_KEY_ID" || got[2].Service != "aws" || !got[2].Sensitive {
		t.Errorf("explicit AWS label = %+v", got[2])
	}

	report := Analyze("token bucket is full\nmodel context window is large\n")
	if len(report.Suggestions) != 0 || len(report.Warnings) != 2 {
		t.Fatalf("prose was over-detected: %+v", report)
	}
}

func TestReviewSafetyAndFormats(t *testing.T) {
	t.Run("natural language and duplicates", func(t *testing.T) {
		r := Analyze("my email address is first@example.org\nsecond@example.org\nfirst@example.org\nunrecognized sentence")
		if len(r.Suggestions) != 2 || r.Suggestions[1].Name != "EMAIL_2" || len(r.Warnings) == 0 {
			t.Fatalf("report = %+v", r)
		}
		if r.Suggestions[0].ID == r.Suggestions[1].ID {
			t.Fatal("IDs must be unique")
		}
	})
	for _, text := range []string{`{"openai":{"apiKey":"dummy-secret","model":"small-model"}}`, "openai:\n  api_key: dummy-secret\n  model: small-model"} {
		got := Parse(text)
		if len(got) != 2 || got[0].Name != "OPENAI_API_KEY" || !got[0].Sensitive || got[1].Sensitive {
			t.Errorf("structured input: %+v", got)
		}
	}
	for _, value := range []string{"https://user:password@example.org", "https://example.org?token=credential", "postgres://user:password@localhost/db", "an-unknown-string"} {
		if !sensitive("SETTING", value) {
			t.Errorf("unsafe config default for test value")
		}
	}
	got := Parse(`curl -H 'Authorization: Bearer dummy-token' -H 'x-api-key: another-key' https://example.org`)
	if len(got) != 3 || !got[0].Sensitive || !got[1].Sensitive || got[2].Sensitive {
		t.Fatalf("curl = %+v", got)
	}
	if got := Parse(`{"KEY":"first","KEY":"second"}`); len(got) != 2 || got[1].Name != "KEY_2" {
		t.Fatal("duplicate structured values were lost")
	}
	if got := Parse(`["first@example.org","second@example.org"]`); len(got) != 2 {
		t.Fatal("bare structured values were lost")
	}
}

func parseBareValueCount(text string) int {
	count := 0
	parseBareValue(text, func(Suggestion) { count++ })
	return count
}
