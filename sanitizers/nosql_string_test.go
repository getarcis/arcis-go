package sanitizers

import "testing"

// String-form NoSQL operator detection. nosqlDangerousKeys covers the
// object-KEY form ({"$gt": ...}); these tests cover operators that arrive
// as string VALUES (query params, mongo-shell payloads). This closes the
// Go-vs-Python parity gap that left string-form NoSQL undetected.

func TestDetectNoSQLString_Positives(t *testing.T) {
	for _, payload := range []string{
		"$where: '1==1'",
		"[$ne]=1",
		`{"$gt": ""}`,
		"user[$gt]=admin",
		"$regex:.*",
		"$where: function() { return true; }",
		"name=admin&age[$gt]=0",
		`$function: "return 1"`,
	} {
		if !DetectNoSQLString(payload) {
			t.Errorf("expected DetectNoSQLString(%q) = true", payload)
		}
	}
}

func TestDetectNoSQLString_Negatives(t *testing.T) {
	// The trailing \b word boundary keeps $-prefixed plain words ($invoice,
	// $order, $index) from matching the $in / $or / $index operator prefixes.
	for _, benign := range []string{
		"$invoice total",
		"$order summary",
		"price is $5.00",
		"$index of array",
		"$model name",
		"regular user comment",
		"The cost is great today",
		"email@example.com",
		"",
	} {
		if DetectNoSQLString(benign) {
			t.Errorf("expected DetectNoSQLString(%q) = false (false positive)", benign)
		}
	}
}

func TestScanThreats_NoSQLStringClassifiesAsNoSQL(t *testing.T) {
	// A string-form operator with nothing else matching should attribute to
	// nosql (last in the scan chain).
	hit := ScanThreats("$where: '1==1'")
	if hit == nil {
		t.Fatal("expected a hit on $where payload")
	}
	if hit.Vector != "nosql" {
		t.Errorf("expected vector=nosql, got %q", hit.Vector)
	}
}
