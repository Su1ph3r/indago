package detector

import (
	"testing"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

func TestLuhnValid(t *testing.T) {
	valid := []string{
		"4111111111111111", // Visa test
		"5500000000000004", // Mastercard test
		"340000000000009",  // Amex test
		"6011000000000004", // Discover test
		"4242424242424242", // Stripe test
	}
	for _, cc := range valid {
		if !luhnValid(cc) {
			t.Errorf("luhnValid(%q) = false, expected true (valid card number)", cc)
		}
	}
}

func TestLuhnValid_Invalid(t *testing.T) {
	invalid := []string{
		"4111111111111112", // Off by one
		"1234567890123456", // Random
		"123",              // Too short
	}
	for _, cc := range invalid {
		if luhnValid(cc) {
			t.Errorf("luhnValid(%q) = true, expected false (invalid card number)", cc)
		}
	}
}

func TestLuhnValid_TooShort(t *testing.T) {
	if luhnValid("123456789012") {
		t.Error("luhnValid should reject numbers shorter than 13 digits")
	}
}

func TestLuhnValid_TooLong(t *testing.T) {
	if luhnValid("12345678901234567890") {
		t.Error("luhnValid should reject numbers longer than 19 digits")
	}
}

func TestValidateSSN_Valid(t *testing.T) {
	body := `{"user": "John", "ssn": "123-45-6789", "name": "Doe"}`
	if !validateSSN("123-45-6789", body) {
		t.Error("validateSSN should return true when SSN keyword is nearby and format is valid")
	}
}

func TestValidateSSN_NoKeyword(t *testing.T) {
	body := `{"user": "John", "phone": "123-45-6789", "name": "Doe"}`
	if validateSSN("123-45-6789", body) {
		t.Error("validateSSN should return false when no SSN keyword is nearby")
	}
}

func TestValidateSSN_InvalidPrefix000(t *testing.T) {
	body := `{"ssn": "000-45-6789"}`
	if validateSSN("000-45-6789", body) {
		t.Error("validateSSN should reject area code 000")
	}
}

func TestValidateSSN_InvalidPrefix666(t *testing.T) {
	body := `{"ssn": "666-45-6789"}`
	if validateSSN("666-45-6789", body) {
		t.Error("validateSSN should reject area code 666")
	}
}

func TestValidateSSN_InvalidPrefix900(t *testing.T) {
	body := `{"ssn": "900-45-6789"}`
	if validateSSN("900-45-6789", body) {
		t.Error("validateSSN should reject area code >= 900")
	}
}

func TestValidateSSN_InvalidGroup00(t *testing.T) {
	body := `{"ssn": "123-00-6789"}`
	if validateSSN("123-00-6789", body) {
		t.Error("validateSSN should reject group 00")
	}
}

func TestValidateSSN_InvalidSerial0000(t *testing.T) {
	body := `{"ssn": "123-45-0000"}`
	if validateSSN("123-45-0000", body) {
		t.Error("validateSSN should reject serial 0000")
	}
}

func TestValidateSSN_SocialSecurityKeyword(t *testing.T) {
	body := `{"social_security": "123-45-6789"}`
	if !validateSSN("123-45-6789", body) {
		t.Error("validateSSN should accept social_security keyword")
	}
}

func TestValidateSSN_SocialSecurityHyphenated(t *testing.T) {
	body := `{"social-security": "123-45-6789"}`
	if !validateSSN("123-45-6789", body) {
		t.Error("validateSSN should accept social-security keyword")
	}
}

func TestValidateSSN_MatchNotInBody(t *testing.T) {
	body := `{"ssn": "999-99-9999"}`
	if validateSSN("123-45-6789", body) {
		t.Error("validateSSN should return false when match is not found in body")
	}
}

func newDummyReq() *payloads.FuzzRequest {
	return &payloads.FuzzRequest{
		Endpoint: types.Endpoint{Method: "GET", Path: "/test"},
		Payload:  payloads.Payload{Type: "test", Value: "test"},
	}
}

func TestDataLeakDetector_APIKey(t *testing.T) {
	d := NewDataLeakDetector()
	// Use a format that matches the regex: api_key=<value> or api_key: <value> (not JSON-quoted key)
	resp := &types.HTTPResponse{Body: `api_key: test_key_abcdefghijklmnopqrstuvwxyz1234`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "API Key Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected API Key finding")
	}
}

func TestDataLeakDetector_APIKeyEqualsFormat(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `apikey=abcdefghijklmnopqrstuvwxyz1234`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "API Key Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected API Key finding for equals-format key")
	}
}

func TestDataLeakDetector_AWSCredentials(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"key": "AKIAIOSFODNN7EXAMPLE"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "AWS Credentials Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected AWS credentials finding")
	}
}

func TestDataLeakDetector_AWSSecretKey(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `aws_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "AWS Credentials Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected AWS secret key finding")
	}
}

func TestDataLeakDetector_PrivateKey(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Private Key Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected private key finding")
	}
}

func TestDataLeakDetector_PrivateKeyNoRSA(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg..."}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Private Key Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected private key finding for non-RSA key")
	}
}

func TestDataLeakDetector_JWTToken(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "JWT Token Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected JWT token finding")
	}
}

func TestDataLeakDetector_PasswordInJSON(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"username":"admin","password":"secret123"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Password in Response" {
			found = true
		}
	}
	if !found {
		t.Error("expected password finding")
	}
}

func TestDataLeakDetector_PasswordKeywordOnly_NoFinding(t *testing.T) {
	d := NewDataLeakDetector()
	// The word "password" appears but not as a JSON key with a value
	resp := &types.HTTPResponse{Body: `{"error":"password is required"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	for _, f := range findings {
		if f.Title == "Password in Response" {
			t.Error("keyword-only 'password' should NOT trigger finding")
		}
	}
}

func TestDataLeakDetector_SecretInJSON(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"secret":"my_super_secret_value"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Password in Response" {
			found = true
		}
	}
	if !found {
		t.Error("expected password finding for 'secret' key in JSON")
	}
}

func TestDataLeakDetector_CreditCard_ValidLuhn(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"card":"4111111111111111"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Credit Card Number Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected credit card finding for valid Luhn number")
	}
}

func TestDataLeakDetector_CreditCard_InvalidLuhn(t *testing.T) {
	d := NewDataLeakDetector()
	// Matches CC regex format but fails Luhn
	resp := &types.HTTPResponse{Body: `{"card":"4111111111111112"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	for _, f := range findings {
		if f.Title == "Credit Card Number Exposed" {
			t.Error("credit card with invalid Luhn should NOT produce finding")
		}
	}
}

func TestDataLeakDetector_CreditCard_Mastercard(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"card":"5500000000000004"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Credit Card Number Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected credit card finding for Mastercard number")
	}
}

// --- Credit card contextual validation tests ---

func TestValidateCreditCardContext_CardField(t *testing.T) {
	body := `{"card_number":"4111111111111111"}`
	if !validateCreditCardContext("4111111111111111", body) {
		t.Error("should accept when field name contains 'card'")
	}
}

func TestValidateCreditCardContext_PaymentField(t *testing.T) {
	body := `{"payment_card":"4111111111111111"}`
	if !validateCreditCardContext("4111111111111111", body) {
		t.Error("should accept when field name contains 'payment'")
	}
}

func TestValidateCreditCardContext_CreditField(t *testing.T) {
	body := `{"credit_card":"4111111111111111"}`
	if !validateCreditCardContext("4111111111111111", body) {
		t.Error("should accept when field name contains 'credit'")
	}
}

func TestValidateCreditCardContext_BillingField(t *testing.T) {
	body := `{"billing_number":"4111111111111111"}`
	if !validateCreditCardContext("4111111111111111", body) {
		t.Error("should accept when field name contains 'billing'")
	}
}

func TestValidateCreditCardContext_PANField(t *testing.T) {
	body := `{"pan":"4111111111111111"}`
	if !validateCreditCardContext("4111111111111111", body) {
		t.Error("should accept when field name is 'pan'")
	}
}

func TestValidateCreditCardContext_CCPrefixField(t *testing.T) {
	body := `{"cc_number":"4111111111111111"}`
	if !validateCreditCardContext("4111111111111111", body) {
		t.Error("should accept when field name starts with 'cc_'")
	}
}

func TestValidateCreditCardContext_IDField_Reject(t *testing.T) {
	body := `{"id":"4111111111111111"}`
	if validateCreditCardContext("4111111111111111", body) {
		t.Error("should reject when field name is 'id'")
	}
}

func TestValidateCreditCardContext_UserIDField_Reject(t *testing.T) {
	body := `{"user_id":"4111111111111111"}`
	if validateCreditCardContext("4111111111111111", body) {
		t.Error("should reject when field name is 'user_id'")
	}
}

func TestValidateCreditCardContext_TimestampField_Reject(t *testing.T) {
	body := `{"timestamp":"4111111111111111"}`
	if validateCreditCardContext("4111111111111111", body) {
		t.Error("should reject when field name is 'timestamp'")
	}
}

func TestValidateCreditCardContext_PhoneField_Reject(t *testing.T) {
	body := `{"phone":"4111111111111111"}`
	if validateCreditCardContext("4111111111111111", body) {
		t.Error("should reject when field name is 'phone'")
	}
}

func TestValidateCreditCardContext_GenericField_Reject(t *testing.T) {
	// A non-card, non-blocklisted field should also be rejected
	body := `{"data":"4111111111111111"}`
	if validateCreditCardContext("4111111111111111", body) {
		t.Error("should reject when field name is generic (no card keyword)")
	}
}

func TestValidateCreditCardContext_RawText_Accept(t *testing.T) {
	// No JSON context — raw text with a card number should be accepted
	body := `Card: 4111111111111111`
	if !validateCreditCardContext("4111111111111111", body) {
		t.Error("should accept card number in raw text (no JSON field context)")
	}
}

func TestValidateCreditCardContext_BookIDField_Reject(t *testing.T) {
	body := `{"book_id":"4111111111111111"}`
	if validateCreditCardContext("4111111111111111", body) {
		t.Error("should reject when field name is 'book_id'")
	}
}

func TestValidateCreditCardContext_ExpField_Reject(t *testing.T) {
	body := `{"exp":"4111111111111111"}`
	if validateCreditCardContext("4111111111111111", body) {
		t.Error("should reject when field name is 'exp'")
	}
}

func TestValidateCreditCardContext_MatchNotInBody(t *testing.T) {
	body := `{"card":"5500000000000004"}`
	if validateCreditCardContext("4111111111111111", body) {
		t.Error("should return false when match is not found in body")
	}
}

// Integration test: VAmPI-style response with user ID that passes Luhn
func TestDataLeakDetector_CreditCard_FalsePositive_UserID(t *testing.T) {
	d := NewDataLeakDetector()
	// Simulates a VAmPI response where a user ID happens to pass Luhn
	resp := &types.HTTPResponse{Body: `{"status":"success","user_id":"4111111111111111","username":"admin","email":"admin@test.com"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	for _, f := range findings {
		if f.Title == "Credit Card Number Exposed" {
			t.Error("user_id field should NOT trigger credit card finding")
		}
	}
}

// Integration test: VAmPI-style response with timestamp-like numeric field
func TestDataLeakDetector_CreditCard_FalsePositive_Timestamp(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"created":"4111111111111111","name":"test"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	for _, f := range findings {
		if f.Title == "Credit Card Number Exposed" {
			t.Error("created field should NOT trigger credit card finding")
		}
	}
}

// Integration test: legitimate credit card in a payment field
func TestDataLeakDetector_CreditCard_Legitimate_PaymentField(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"payment_card":"4111111111111111","amount":"29.99"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Credit Card Number Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected credit card finding when field is 'payment_card'")
	}
}

// Integration test: legitimate credit card in account_number field
func TestDataLeakDetector_CreditCard_Legitimate_AccountNumber(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"account_number":"4111111111111111"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Credit Card Number Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected credit card finding when field is 'account_number'")
	}
}

func TestExtractNearestJSONKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple key", `{"card_number": `, "card_number"},
		{"key with spaces", `{"user_id" : `, "user_id"},
		{"no colon", `{"field" `, ""},
		{"empty", "", ""},
		{"nested", `{"outer":{"inner": `, "inner"},
		{"no quotes before colon", `{field: `, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNearestJSONKey(tt.input)
			if got != tt.expected {
				t.Errorf("extractNearestJSONKey(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDataLeakDetector_SSN_WithContext(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"ssn":"123-45-6789"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "SSN Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected SSN finding when SSN keyword is present")
	}
}

func TestDataLeakDetector_SSN_NoContext(t *testing.T) {
	d := NewDataLeakDetector()
	// Looks like SSN format but no SSN keyword nearby
	resp := &types.HTTPResponse{Body: `{"phone":"123-45-6789"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	for _, f := range findings {
		if f.Title == "SSN Exposed" {
			t.Error("SSN-format number without SSN keyword should NOT produce finding")
		}
	}
}

func TestDataLeakDetector_BulkEmailExposure(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `[
		"user1@example.com",
		"user2@example.com",
		"user3@example.com",
		"user4@example.com",
		"user5@example.com"
	]`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Bulk Email Exposure" {
			found = true
		}
	}
	if !found {
		t.Error("expected bulk email finding when 5 or more emails are present")
	}
}

func TestDataLeakDetector_FewEmails_NoFinding(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `["user1@example.com","user2@example.com"]`}
	findings := d.Detect(resp, newDummyReq(), nil)
	for _, f := range findings {
		if f.Title == "Bulk Email Exposure" {
			t.Error("fewer than 5 emails should NOT trigger bulk email finding")
		}
	}
}

func TestDataLeakDetector_InternalIP(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"server":"192.168.1.100"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Internal IP Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected internal IP finding")
	}
}

func TestDataLeakDetector_InternalIP_10Network(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"debug_info":"host=10.0.0.1"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Internal IP Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected internal IP finding for 10.x.x.x network")
	}
}

func TestDataLeakDetector_InternalIP_172Network(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"debug_info":"host=172.16.0.1"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Internal IP Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected internal IP finding for 172.16.x.x network")
	}
}

func TestDataLeakDetector_DatabaseConnectionString(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `mongodb://admin:password123@db.example.com:27017/mydb`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Database Connection String" {
			found = true
		}
	}
	if !found {
		t.Error("expected database connection string finding")
	}
}

func TestDataLeakDetector_DatabaseConnectionString_Postgres(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `postgres://user:pass@localhost:5432/db`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Database Connection String" {
			found = true
		}
	}
	if !found {
		t.Error("expected database connection string finding for postgres")
	}
}

func TestDataLeakDetector_SlackToken(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"token":"xoxb-1234567890-abcdefghij"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Slack Token Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected Slack token finding")
	}
}

func TestDataLeakDetector_GitHubToken(t *testing.T) {
	d := NewDataLeakDetector()
	// ghp_ followed by exactly 36 alphanumeric characters
	resp := &types.HTTPResponse{Body: `{"token":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "GitHub Token Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected GitHub token finding")
	}
}

func TestDataLeakDetector_GoogleAPIKey(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"key":"AIzaSyA1234567890abcdefghijklmnopqrstuv"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Google API Key Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected Google API key finding")
	}
}

func TestDataLeakDetector_BaselineSuppression(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `api_key: test_key_abcdefghijklmnopqrstuvwxyz1234`}
	baseline := &types.HTTPResponse{Body: `api_key: test_key_abcdefghijklmnopqrstuvwxyz1234`}
	findings := d.Detect(resp, newDummyReq(), baseline)
	for _, f := range findings {
		if f.Title == "API Key Exposed" {
			t.Error("finding should be suppressed when pattern exists in baseline")
		}
	}
}

func TestDataLeakDetector_BaselineNull(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `api_key: test_key_abcdefghijklmnopqrstuvwxyz1234`}
	findings := d.Detect(resp, newDummyReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "API Key Exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding when baseline is nil")
	}
}

func TestDataLeakDetector_BaselinePartialSuppression(t *testing.T) {
	d := NewDataLeakDetector()
	// Response has both an API key and a private key, baseline only has the API key
	resp := &types.HTTPResponse{Body: "api_key: test_key_abcdefghijklmnopqrstuvwxyz1234\n-----BEGIN RSA PRIVATE KEY-----\nMIIEp..."}
	baseline := &types.HTTPResponse{Body: `api_key: test_key_abcdefghijklmnopqrstuvwxyz1234`}
	findings := d.Detect(resp, newDummyReq(), baseline)
	foundAPIKey := false
	foundPrivateKey := false
	for _, f := range findings {
		if f.Title == "API Key Exposed" {
			foundAPIKey = true
		}
		if f.Title == "Private Key Exposed" {
			foundPrivateKey = true
		}
	}
	if foundAPIKey {
		t.Error("API key finding should be suppressed by baseline")
	}
	if !foundPrivateKey {
		t.Error("private key finding should NOT be suppressed (not in baseline)")
	}
}

func TestDataLeakDetector_CleanResponse(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"status":"ok","message":"Hello World"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean response, got %d", len(findings))
	}
}

func TestDataLeakDetector_EmptyBody(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: ""}
	findings := d.Detect(resp, newDummyReq(), nil)
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty body, got %d", len(findings))
	}
}

func TestDataLeakDetector_FindingSeverity(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `{"key": "AKIAIOSFODNN7EXAMPLE"}`}
	findings := d.Detect(resp, newDummyReq(), nil)
	for _, f := range findings {
		if f.Title == "AWS Credentials Exposed" {
			if f.Severity != types.SeverityCritical {
				t.Errorf("AWS credentials finding severity = %q, want %q", f.Severity, types.SeverityCritical)
			}
			if f.Confidence != types.ConfidenceHigh {
				t.Errorf("AWS credentials finding confidence = %q, want %q", f.Confidence, types.ConfidenceHigh)
			}
			if f.CWE != "CWE-798" {
				t.Errorf("AWS credentials finding CWE = %q, want %q", f.CWE, "CWE-798")
			}
			if f.Type != "data_leak" {
				t.Errorf("finding type = %q, want %q", f.Type, "data_leak")
			}
			return
		}
	}
	t.Error("expected AWS credentials finding")
}

func TestDataLeakDetector_FindingHasID(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: "-----BEGIN PRIVATE KEY-----\ndata..."}
	findings := d.Detect(resp, newDummyReq(), nil)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].ID == "" {
		t.Error("finding ID should not be empty")
	}
}

func TestDataLeakDetector_MultipleFindings(t *testing.T) {
	d := NewDataLeakDetector()
	resp := &types.HTTPResponse{Body: `AKIAIOSFODNN7EXAMPLE -----BEGIN RSA PRIVATE KEY-----`}
	findings := d.Detect(resp, newDummyReq(), nil)
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
	titles := make(map[string]bool)
	for _, f := range findings {
		titles[f.Title] = true
	}
	if !titles["AWS Credentials Exposed"] {
		t.Error("expected AWS credentials finding")
	}
	if !titles["Private Key Exposed"] {
		t.Error("expected private key finding")
	}
}

func TestDataLeakDetector_AddRule(t *testing.T) {
	d := NewDataLeakDetector()
	initialCount := len(d.rules)
	d.AddRule(&LeakRule{
		Name:     "Custom Secret",
		Severity: types.SeverityHigh,
	})
	if len(d.rules) != initialCount+1 {
		t.Errorf("expected %d rules after AddRule, got %d", initialCount+1, len(d.rules))
	}
}
