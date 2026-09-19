package server

import (
	"testing"

	"github.com/awcullen/opcua/ua"
)

func TestWithSecurityPolicyModesFiltersEndpoints(t *testing.T) {
	srv := createTestServer(t)
	if err := WithSecurityPolicyNone(true)(srv); err != nil {
		t.Fatal(err)
	}
	if err := WithSecurityPolicyModes(map[string][]ua.MessageSecurityMode{
		ua.SecurityPolicyURINone:           {ua.MessageSecurityModeNone},
		ua.SecurityPolicyURIBasic256Sha256: {ua.MessageSecurityModeSignAndEncrypt},
	})(srv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	endpoints := srv.buildEndpointDescriptions()
	if len(endpoints) != 2 {
		t.Fatalf("endpoints=%#v", endpoints)
	}
	if endpoints[0].SecurityPolicyURI != ua.SecurityPolicyURINone || endpoints[0].SecurityMode != ua.MessageSecurityModeNone {
		t.Fatalf("none endpoint=%#v", endpoints[0])
	}
	if endpoints[1].SecurityPolicyURI != ua.SecurityPolicyURIBasic256Sha256 || endpoints[1].SecurityMode != ua.MessageSecurityModeSignAndEncrypt {
		t.Fatalf("secure endpoint=%#v", endpoints[1])
	}
}
