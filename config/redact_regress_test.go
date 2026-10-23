package config

import (
	"strings"
	"testing"
)

func TestRegressionRedact(t *testing.T) {
	for _, dsn := range []string{
		"postgres://app:s3cret@db:5432/x?sslmode=disable",
		"host=db user=app password=s3cret dbname=x",
		"postgres://app:s3cret@db:abc/x",
		"postgres://app@db/x?password=s3cret",
	} {
		if out := Redact(dsn); strings.Contains(out, "s3cret") {
			t.Errorf("password leaked: %s -> %s", dsn, out)
		}
	}
}
