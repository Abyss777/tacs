// Wrapper for connecting and querying LDAP
package ldap

import (
        "crypto/tls"
	"encoding/base64"
        "strings"
	"fmt"
	l "log/slog"
	"os"
	ld "github.com/go-ldap/ldap/v3"
)

// LDAP_matching_rule_in_chain - LDAP operator that allows you to recursively search for an object in subgroups
const LDAP_matching_rule_in_chain string = ":1.2.840.113556.1.4.1941:"

// Connect - performs connection to LDAP by provided parameters
// and returns the connection object.
//
// Requires `TACS_LDAP_SERVER` and `TACS_LDAP_PORT` in environment variables
//
// If `TACS_LDAP_CERT` and `TACS_LDAP_KEY` are set, TLS is enabled and traffic is encrypted.
// Minimum TLS version = 1.2
//
// If `TACS_LDAP_USER` and `TACS_LDAP_PASSWORD` are set, Bind() is executed.
func Connect() (*ld.Conn, error) {
	host := os.Getenv("TACS_LDAP_SERVER")
	port := os.Getenv("TACS_LDAP_PORT")
        useSSL := os.Getenv("TACS_LDAP_SSL")
        useTLS := os.Getenv("TACS_LDAP_TLS")
	username := os.Getenv("TACS_LDAP_USER")
	password := os.Getenv("TACS_LDAP_PASSWORD")

        url := fmt.Sprintf("ldap://%s:%s", host, port)
        if strings.ToLower(useSSL) == "true"  || port == "636" {
                url = fmt.Sprintf("ldaps://%s:%s", host, port)
        }
        conn, err := ld.DialURL(url, ld.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
        if err != nil {
                l.Error("dialing error", l.String("host", host), l.String("port", port), l.Any("err", err))
                return nil, err
        }

	if strings.ToLower(useTLS) == "true" {

		// Trying to switch to TLS
		err := conn.StartTLS(&tls.Config{InsecureSkipVerify: true});
		if err != nil {
			l.Error("error of switching to secure channel", l.Any("err", err))
			return conn, err
		}

	}
	// Authenticate under the user, in case of failure - just return the connection
	if username != "" && password != "" {
		if err := conn.Bind(username, password); err != nil {
			l.Error("LDAP authentication error",
				l.String("username", username),
				l.String("host", host),
				l.String("post", port),
				l.Any("err", err),
			)
			return conn, err
		}
	}
	return conn, nil
}

// Accepts query data and returns data from LDAP.
//
// The requested attributes must be in the exact case as they are in LDAP,
// otherwise they cannot be retrieved from the returned data.
//
// Returns raw data in base64 format
func Request(
	conn *ld.Conn,
	searchBase, filter string, requestAttributes []string, rawFormat bool) (
	[]map[string][]string, error,
) {
	searchRequest := ld.NewSearchRequest(
		searchBase,

		ld.ScopeWholeSubtree,
		ld.NeverDerefAliases, 0, 0, false,

		filter, requestAttributes, nil)

	// Запрос к LDAP

	sr, err := conn.Search(searchRequest)
	if err != nil {
		if ld.IsErrorAnyOf(err, ld.LDAPResultNoSuchObject) {
			l.Warn("no objects found",
				l.String("baseDn", searchBase),
				l.String("ldapFilter", filter),
				l.Any("requestAttributes", requestAttributes))
		} else {
			l.Error("LDAP search error",
				l.String("baseDn", searchBase),
				l.String("ldapFilter", filter),
				l.Any("requestAttributes", requestAttributes),
				l.Any("err", err))
		}
		return nil, err
	}

	// Response parsing
	var objects []map[string][]string = make([]map[string][]string, 0)

	for _, entry := range sr.Entries {
		var obj map[string][]string = make(map[string][]string)

		obj["dn"] = []string{entry.DN}
		for _, attr := range requestAttributes {
			if rawFormat {
				rawValues := entry.GetRawAttributeValues(attr)

				var encObj []string
				for _, b := range rawValues {
					encObj = append(encObj, base64.StdEncoding.EncodeToString(b))
				}

				obj[attr] = encObj
				continue
			}
			obj[attr] = entry.GetAttributeValues(attr)
		}
		objects = append(objects, obj)
	}
	return objects, nil
}
