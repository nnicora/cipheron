package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

// oidShortNames maps ASN.1 OID strings to their RFC 2253 short names.
// This is used to represent DN attribute types in a human-readable form.
var oidShortNames = map[string]string{
	"2.5.4.3":                    "CN",     // commonName
	"2.5.4.7":                    "L",      // localityName
	"2.5.4.8":                    "ST",     // stateOrProvinceName
	"2.5.4.10":                   "O",      // organizationName
	"2.5.4.11":                   "OU",     // organizationalUnitName
	"2.5.4.6":                    "C",      // countryName
	"2.5.4.9":                    "STREET", // streetAddress
	"0.9.2342.19200300.100.1.25": "DC",     // domainComponent
	"0.9.2342.19200300.100.1.1":  "UID",    // userID
}

// escapeRFC2253 escapes special characters in a DN attribute value
// according to RFC 2253 rules. This includes characters like commas,
// plus signs, quotes, backslashes, and more. Leading/trailing spaces
// and leading '#' are also escaped.
//
// val: the string value to escape
// Returns the escaped string safe for inclusion in an RFC 2253 DN
func escapeRFC2253(val string) string {
	var b strings.Builder

	for i, r := range val {
		if r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';' || r == '=' {
			b.WriteRune('\\')
		}
		// Escape leading or trailing spaces or leading '#'
		if (i == 0 && (r == ' ' || r == '#')) || (i == len(val)-1 && r == ' ') {
			b.WriteRune('\\')
		}

		b.WriteRune(r)
	}

	return b.String()
}

// formatRDNSequence takes a pkix.RDNSequence (ASN.1 parsed DN)
// and formats it into a string following RFC 2253 rules, matching Envoy's format.
//
// - RDNs are printed in reverse order (most specific first).
// - Multiple attributes in a single RDN are joined with '+'.
// - Attribute types use short names when known (e.g. CN, OU).
// - Attribute values are escaped properly.
//
// rdns: the RDNSequence to format
// Returns the formatted DN string.
func formatRDNSequence(rdns pkix.RDNSequence) string {
	var parts []string
	// Reverse the RDN order
	for i := len(rdns) - 1; i >= 0; i-- {
		var attrs []string

		for _, atv := range rdns[i] {
			name := oidShortNames[atv.Type.String()]
			if name == "" {
				name = atv.Type.String()
			}

			val := fmt.Sprintf("%v", atv.Value)
			attrs = append(attrs, fmt.Sprintf("%s=%s", name, escapeRFC2253(val)))
		}

		parts = append(parts, strings.Join(attrs, "+"))
	}

	return strings.Join(parts, ",")
}

// formatSubject extracts the ASN.1 raw subject field from a certificate,
// parses it into an RDNSequence, and returns the RFC 2253 formatted string.
//
// cert: the X.509 certificate to extract subject from
// Returns the formatted subject string or an empty string on parse failure.
func FormatSubject(cert *x509.Certificate) string {
	var rdnSeq pkix.RDNSequence

	_, err := asn1.Unmarshal(cert.RawSubject, &rdnSeq)
	if err != nil {
		return ""
	}

	return formatRDNSequence(rdnSeq)
}

// formatIssuer extracts the ASN.1 raw issuer field from a certificate,
// parses it into an RDNSequence, and returns the RFC 2253 formatted string.
//
// cert: the X.509 certificate to extract issuer from
// Returns the formatted issuer string or an empty string on parse failure.
func FormatIssuer(cert *x509.Certificate) string {
	var rdnSeq pkix.RDNSequence

	_, err := asn1.Unmarshal(cert.RawIssuer, &rdnSeq)
	if err != nil {
		return ""
	}

	return formatRDNSequence(rdnSeq)
}
