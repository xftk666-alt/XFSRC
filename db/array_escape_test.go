package db

import (
	"encoding/json"
	"testing"
)

// PostgreSQL array literals use backslash as an escape character. Encoding a
// value without doubling it first silently corrupts the stored text: `a\b`
// lands in the column as `ab`. These tests pin the encoder and, when a database
// is available, prove the round trip through PostgreSQL itself.
func TestMarshalStringArrayEscapesBackslashes(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"plain", []string{"alpha", "beta"}, `{"alpha","beta"}`},
		{"quote", []string{`a"b`}, `{"a\"b"}`},
		{"backslash", []string{`a\b`}, `{"a\\b"}`},
		{"trailing backslash", []string{`end\`}, `{"end\\"}`},
		{"windows path", []string{`C:\Users\x`}, `{"C:\\Users\\x"}`},
		{"backslash then quote", []string{`a\"b`}, `{"a\\\"b"}`},
		{"empty element", []string{""}, `{""}`},
		{"empty list", nil, `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := marshalStringArray(tc.in); got != tc.want {
				t.Fatalf("marshalStringArray(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// The jsonb[] encoder and the text[] encoder must agree on element quoting; they
// had drifted apart once already.
func TestArrayEncodersShareQuoting(t *testing.T) {
	if got, want := quotePGArrayElement(`a\b"c`), `"a\\b\"c"`; got != want {
		t.Fatalf("quotePGArrayElement = %s, want %s", got, want)
	}
}

// Round trip through PostgreSQL: this is the assertion that would have caught
// the original bug, because a corrupted literal still inserts successfully.
func TestMarshalStringArrayRoundTripsThroughPostgres(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	in := []string{`a\b`, `quote"inside`, `C:\path\to`, `plain`, ``, `tab\there`}
	literal := marshalStringArray(in)

	var asJSON string
	if err := d.QueryRow(`SELECT array_to_json($1::text[])::text`, literal).Scan(&asJSON); err != nil {
		t.Fatalf("PostgreSQL rejected the literal %s: %v", literal, err)
	}
	var got []string
	if err := json.Unmarshal([]byte(asJSON), &got); err != nil {
		t.Fatalf("decode %s: %v", asJSON, err)
	}
	if len(got) != len(in) {
		t.Fatalf("length = %d, want %d (got %q)", len(got), len(in), got)
	}
	for i := range in {
		if got[i] != in[i] {
			t.Errorf("element %d = %q, want %q", i, got[i], in[i])
		}
	}
}
