package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Use the terraform plugin sdk testing framework for acceptance testing policyattachment lifecycle
func TestAccPolicyAttachment_basic(t *testing.T) {
	var bnnPolicyAttachment policyattachment.GetBody

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicyAttachmentDestroy(t, &bnnPolicyAttachment),
		Steps: []resource.TestStep{
			{
				// Create the policy attachment and validate it
				Config: testAccPolicyAttachment_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicyAttachment("banyan_policy_attachment.acceptance", &bnnPolicyAttachment),
					resource.TestCheckResourceAttrPtr("banyan_policy_attachment.acceptance", "attached_to_id", &bnnPolicyAttachment.AttachedToID),
					resource.TestCheckResourceAttrPtr("banyan_policy_attachment.acceptance", "policy_id", &bnnPolicyAttachment.PolicyID),
				),
			},
			{
				// Update the policy attachment to use banyan_policy.acceptance_update and assert this change is reflected correctly
				Config: testAccPolicyAttachment_update(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicyAttachment("banyan_policy_attachment.acceptance", &bnnPolicyAttachment),
					testAccCheckPolicyAttachmentUpdated(t, &bnnPolicyAttachment, "banyan_policy_attachment.acceptance"),
					resource.TestCheckResourceAttrPtr("banyan_policy_attachment.acceptance", "policy_id", &bnnPolicyAttachment.PolicyID),
				),
			},
		},
	})
}

// Checks that the resource with the name resourceName exists and returns the policyattachment object from the Banyan API
func testAccCheckExistingPolicyAttachment(resourceName string, policyAttachment *policyattachment.GetBody) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found %q", rs)
		}
		resp, _, err := testAccClient.PolicyAttachment.Get(rs.Primary.Attributes["attached_to_id"], rs.Primary.Attributes["attached_to_type"])
		if err != nil {
			return err
		}
		if resp.PolicyID != rs.Primary.Attributes["policy_id"] {
			return fmt.Errorf("expected resource id %q got %q instead", resp.PolicyID, rs.Primary.ID)
		}
		*policyAttachment = resp
		return nil
	}
}

// Asserts using the API that the groups for the policyattachment were updated
func testAccCheckPolicyAttachmentUpdated(t *testing.T, bnnPolicyAttachment *policyattachment.GetBody, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found %q", rs)
		}

		if bnnPolicyAttachment.AttachedToID != rs.Primary.Attributes["attached_to_id"] {
			return fmt.Errorf("incorrect attachment_id, expected %s, got: %s", bnnPolicyAttachment.AttachedToID, rs.Primary.Attributes["attached_to_id"])
		}
		return nil
	}
}

// Uses the API to check that the policyattachment was destroyed
func testAccCheckPolicyAttachmentDestroy(t *testing.T, policyAttachment *policyattachment.GetBody) resource.TestCheckFunc {
	emptyPolicyAttachment := policyattachment.GetBody{}
	return func(s *terraform.State) error {
		r, _, err := testAccClient.PolicyAttachment.Get(policyAttachment.AttachedToID, policyAttachment.AttachedToType)
		assert.Equal(t, r, emptyPolicyAttachment)
		return err
	}
}

// Returns terraform configuration for the policyattachment. Takes in custom name.
func testAccPolicyAttachment_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acceptance" {
  cluster     = "dev05-banyan"
  name        = %q
  description = "acceptance test service"
  metadatatags {
    domain           = "test2v.com"
    port             = 1111
    protocol         = "https"
    service_app_type = "WEB"
    user_facing      = false
    template         = "WEB_USER"
    app_listen_port  = 9191
    include_domains  = ["test2v.com"]
  }

  client_cidrs {
    clusters = ["cluster"]
    cidr_address {
      cidr  = "10.0.1.0/24"
      ports = "888"
    }
    host_tag_selector = [
      { testkey = "testvalue" },
      { testkey2 = "testvalue2" }
    ]
  }

  backend {
    allow_patterns {
      hostnames = ["differentone.com", "foo.bar.baz"]
      cidrs     = ["10.0.1.0/24"]
      ports {
        port_list = [88, 99]
        port_range {
          min = 8
          max = 9
        }
      }
    }

    dns_overrides = {
      "internal.mysvc.com" = "10.23.0.1"
      "exposed.service.com" : "internal.myservice.com"
    }

    connector_name = "hahah-connector-name"
    http_connect = true
    whitelist = ["allowme.com", "newurl.org"]

    target {
      client_certificate = true
      name               = "targetbacknd"
      port               = 1515
      tls                = true
      tls_insecure       = true
    }
  }

  frontend {
    cidr = "127.44.111.14/32"
    port = 1112
  }

  host_tag_selector = [
    { site_name = "sitename" }
  ]

  tls_sni = [%q]

  cert_settings {
    letsencrypt = false
    dns_names   = ["hello_dns_name", "dns_name2"]
    custom_tls_cert {
      enabled   = false
      cert_file = "asdf"
      key_file  = "asdf"
    }
  }

  http_settings {
    enabled = true
    oidc_settings {
      enabled = true
      service_domain_name = %q
      post_auth_redirect_path = "/some/path"
      api_path = "/api"
      suppress_device_trust_verification = false
      trust_callbacks = {
        "somecallback" : "ohhey"
      }
    }
    http_health_check {
      enabled      = true
      addresses    = ["88.99.101.2"]
      method       = "GET"
      path         = "/path"
      user_agent   = "chrome"
      from_address = ["11.11.11.99"]
      https        = true
    }
    exempted_paths {
      enabled = true
      patterns {
        template          = "USER"
        source_cidrs      = ["10.0.0.1/24"]
        methods           = ["GET", "POST"]
        paths             = ["/path1", "/path2"]
        mandatory_headers = ["someheader", "other_header"]
      }
    }
    headers = {
      "foo" = "bar"
    }
    token_loc {
      query_param = "somequeryparam"
      authorization_header = true
      custom_header = "customheaderhere"
    }
  }
}

resource "banyan_policy" "acceptance" {
  name        = %q
  description = "realdescription"
  metadatatags {
    template = "USER"
  }
  access {
    roles = ["ANY", "HI"]
    rules {
      conditions {
        trust_level = "High"
      }
      l7_access {
        resources = ["*"]
        actions   = ["*"]
      }
    }
  }
  exception {
    source_address = ["127.0.0.1"]
  }
  disable_tls_client_authentication = true
  l7_protocol                       = "http"
}

resource "banyan_policy_attachment" "acceptance" {
  policy_id = banyan_policy.acceptance.id
  attached_to_type = "service"
  attached_to_id = banyan_service.acceptance.id
  is_enforcing = true
}
`, name, name, name, name)
}

// Returns terraform configuration for an updated version of the policyattachment with additional groups. Takes in custom name.
func testAccPolicyAttachment_update(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acceptance" {
  cluster     = "dev05-banyan"
  name        = %q
  description = "acceptance test service"
  metadatatags {
    domain           = "test2v.com"
    port             = 1111
    protocol         = "https"
    service_app_type = "WEB"
    user_facing      = false
    template         = "WEB_USER"
    app_listen_port  = 9191
    include_domains  = ["test2v.com"]
  }

  client_cidrs {
    clusters = ["cluster"]
    cidr_address {
      cidr  = "10.0.1.0/24"
      ports = "888"
    }
    host_tag_selector = [
      { testkey = "testvalue" },
      { testkey2 = "testvalue2" }
    ]
  }

  backend {
    allow_patterns {
      hostnames = ["differentone.com", "foo.bar.baz"]
      cidrs     = ["10.0.1.0/24"]
      ports {
        port_list = [88, 99]
        port_range {
          min = 8
          max = 9
        }
      }
    }

    dns_overrides = {
      "internal.mysvc.com" = "10.23.0.1"
      "exposed.service.com" : "internal.myservice.com"
    }

    connector_name = "hahah-connector-name"
    http_connect = true
    whitelist = ["allowme.com", "newurl.org"]

    target {
      client_certificate = true
      name               = "targetbacknd"
      port               = 1515
      tls                = true
      tls_insecure       = true
    }
  }

  frontend {
    cidr = "127.44.111.14/32"
    port = 1112
  }

  host_tag_selector = [
    { site_name = "sitename" }
  ]

  tls_sni = [%q]

  cert_settings {
    letsencrypt = false
    dns_names   = ["hello_dns_name", "dns_name2"]
    custom_tls_cert {
      enabled   = false
      cert_file = "asdf"
      key_file  = "asdf"
    }
  }

  http_settings {
    enabled = true
    oidc_settings {
      enabled = true
      service_domain_name = %q
      post_auth_redirect_path = "/some/path"
      api_path = "/api"
      suppress_device_trust_verification = false
      trust_callbacks = {
        "somecallback" : "ohhey"
      }
    }
    http_health_check {
      enabled      = true
      addresses    = ["88.99.101.2"]
      method       = "GET"
      path         = "/path"
      user_agent   = "chrome"
      from_address = ["11.11.11.99"]
      https        = true
    }
    exempted_paths {
      enabled = true
      patterns {
        template          = "USER"
        source_cidrs      = ["10.0.0.1/24"]
        methods           = ["GET", "POST"]
        paths             = ["/path1", "/path2"]
        mandatory_headers = ["someheader", "other_header"]
      }
    }
    headers = {
      "foo" = "bar"
    }
    token_loc {
      query_param = "somequeryparam"
      authorization_header = true
      custom_header = "customheaderhere"
    }
  }
}

resource "banyan_policy" "acceptance" {
  name        = %q
  description = "realdescription"
  metadatatags {
    template = "USER"
  }
  access {
    roles = ["ANY", "HI"]
    rules {
      conditions {
        trust_level = "High"
      }
      l7_access {
        resources = ["*"]
        actions   = ["*"]
      }
    }
  }
  exception {
    source_address = ["127.0.0.1"]
  }
  disable_tls_client_authentication = true
  l7_protocol                       = "http"
}

resource "banyan_policy_attachment" "acceptance" {
  policy_id = banyan_policy.acceptance.id
  attached_to_type = "service"
  attached_to_id = banyan_service.acceptance.id
  is_enforcing = true
}
`, name, name, name, name)
}