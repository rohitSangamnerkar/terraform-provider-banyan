package banyan

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestSchemaV2Role_known_device(t *testing.T) {
	role_known_device := map[string]interface{}{
		"name":              "UsersRegisteredDevice",
		"description":       "[TF] Users on a device registered with Banyan",
		"user_group":        []interface{}{"Users"},
		"known_device_only": true,
	}
	d := schema.TestResourceDataRaw(t, RoleSchema(), role_known_device)
	role_obj := RoleFromState(d)

	json_spec, _ := os.ReadFile("./specs/role/known-device.json")
	var ref_obj role.CreateRole
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertCreateRoleEqual(t, role_obj, ref_obj)
}

func TestSchemaV2Role_device_ownership(t *testing.T) {
	role_device_ownership := map[string]interface{}{
		"name":             "AdminsCorpDevice",
		"description":      "[TF] Admins on corporate devices",
		"user_group":       []interface{}{"Admins"},
		"device_ownership": []interface{}{"Corporate Dedicated", "Corporate Shared"},
		"platform":         []interface{}{"Windows"},
		"serial_numbers":   []interface{}{"DeviceSerial1"},
	}
	d := schema.TestResourceDataRaw(t, RoleSchema(), role_device_ownership)
	role_obj := RoleFromState(d)

	json_spec, _ := os.ReadFile("./specs/role/device-ownership.json")
	var ref_obj role.CreateRole
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertCreateRoleEqual(t, role_obj, ref_obj)
}

func TestAccV2Role_basic(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			// Creates the security role with the given terraform configuration and asserts that the role is created
			{
				Config: testAccV2Role_basic_create(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_security_role.acceptance", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_security_role.acceptance",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccV2Role_complex_create(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			// Creates the security role with the given terraform configuration and asserts that the role is created
			{
				Config: testAccV2Role_complex_create(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_security_role.acceptance", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_security_role.acceptance",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// update the security role with the given terraform configuration and asserts that the role is updated
			{
				Config: testAccV2Role_complex_update(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_security_role.acceptance", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_security_role.acceptance",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// Returns terraform configuration for the role. Takes in custom name.
func testAccV2Role_basic_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_security_role" "acceptance" {
  name              = "%s"
  description       = "realdescription"
  user_group        = ["group1"]
  device_ownership  = ["Corporate Dedicated", "Corporate Shared", "Employee Owned", "Other"]
  known_device_only = true
  mdm_present       = true
  platform          = ["Windows", "macOS", "Linux", "iOS", "Android", "Unregistered"]
  serial_numbers    = ["First","Second","Third"]
}
`, name)
}

func testAccV2Role_complex_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_security_role" "acceptance" {
 name = %q
  description = "realdescription"
  container_fqdn = ["asdf.asdf"]
  known_device_only = true
  platform = ["macOS", "Android"]
  user_group = ["group1"]
  email = ["john@marsha.com"]
  device_ownership = ["Corporate Dedicated", "Employee Owned"]
  mdm_present = true
  serial_numbers = ["First"]
}
`, name)
}

// Returns terraform configuration for an updated version of the role with additional groups. Takes in custom name.
func testAccV2Role_complex_update(name string) string {
	return fmt.Sprintf(`
resource "banyan_security_role" "acceptance" {
 name = %q
  description = "realdescription"
  container_fqdn = ["asdf.asdf"]
  known_device_only = true
  platform = ["macOS", "Android"]
  user_group = ["group1", "group2"]
  email = ["john@marsha.com"]
  device_ownership = ["Corporate Dedicated", "Employee Owned"]
  mdm_present = true
  serial_numbers = ["First"]
}
`, name)
}
